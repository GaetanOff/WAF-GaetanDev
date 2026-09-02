package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	// Listes officielles Cloudflare (FR-02). En HTTPS exclusivement : la liste
	// récupérée décide qui a le droit de poser CF-Connecting-IP, elle ne peut pas
	// venir d'un transport altérable en chemin.
	ipv4ListURL = "https://www.cloudflare.com/ips-v4"
	ipv6ListURL = "https://www.cloudflare.com/ips-v6"

	// fetchTimeout borne une récupération complète (connexion + lecture). Le
	// rafraîchissement est une tâche de fond : elle échoue plutôt que de traîner.
	fetchTimeout = 10 * time.Second

	// maxPayloadBytes borne la lecture du corps de réponse. Les deux listes font
	// quelques centaines d'octets ; au-delà, ce n'est pas la liste attendue.
	maxPayloadBytes = 64 << 10

	// Bornes de plausibilité de la liste reçue. Cloudflare annonce ~15 préfixes
	// IPv4 et ~7 IPv6 : une liste de 2 entrées est tronquée, une liste de 1000
	// n'est pas la leur.
	minPrefixesPerFamily = 4
	maxPrefixesTotal     = 512

	// Longueurs de préfixe minimales acceptées. C'est le garde-fou central de ce
	// paquet : un préfixe trop large (0.0.0.0/0 à l'extrême) ferait passer
	// N'IMPORTE QUELLE source pour Cloudflare, et donc rendrait CF-Connecting-IP
	// forgeable par tout le monde — exactement la protection que FR-02 assure.
	// Les plus larges plages réellement publiées sont /13 (IPv4) et /29 (IPv6).
	minIPv4PrefixLen = 8
	minIPv6PrefixLen = 19
)

// Updater rafraîchit périodiquement les plages IP Cloudflare depuis les listes
// officielles (FR-02). Il ne remplace la liste en vigueur que par une liste
// complète et validée ; sinon il la laisse intacte et signale l'échec.
type Updater struct {
	interval  time.Duration
	client    *http.Client
	ipv4URL   string
	ipv6URL   string
	onSuccess func(count int)
	onError   func(error)
	// allowInsecureSources n'est posé que par withEndpoints (non exportée) :
	// seuls les tests, qui servent les listes depuis un httptest local en HTTP,
	// désactivent l'exigence HTTPS. Aucun chemin de production ne l'atteint.
	allowInsecureSources bool
}

// Option configure un Updater à la construction.
type Option func(*Updater)

// WithObservers branche les compteurs d'exploitation (métriques, journal) sur
// les deux issues possibles d'un rafraîchissement. Sans eux, un rafraîchissement
// qui échoue en boucle serait invisible.
func WithObservers(onSuccess func(count int), onError func(error)) Option {
	return func(u *Updater) {
		u.onSuccess = onSuccess
		u.onError = onError
	}
}

// withEndpoints redirige les sources. Volontairement NON exportée : aucun
// chemin de production ne doit pouvoir substituer une source en HTTP simple ou
// un hôte tiers aux listes officielles. Les tests, dans le paquet, y accèdent.
func withEndpoints(ipv4URL string, ipv6URL string) Option {
	return func(u *Updater) {
		u.ipv4URL = ipv4URL
		u.ipv6URL = ipv6URL
		u.allowInsecureSources = true
	}
}

// withClient injecte le client HTTP (tests).
func withClient(client *http.Client) Option {
	return func(u *Updater) {
		u.client = client
	}
}

func NewUpdater(interval time.Duration, opts ...Option) *Updater {
	updater := &Updater{
		interval: interval,
		client:   &http.Client{Timeout: fetchTimeout},
		ipv4URL:  ipv4ListURL,
		ipv6URL:  ipv6ListURL,
	}
	for _, opt := range opts {
		opt(updater)
	}
	return updater
}

// Start lance le rafraîchissement : une première tentative immédiate, puis une
// par intervalle, jusqu'à annulation du contexte.
//
// La première tentative a lieu DANS la goroutine, pas avant : le WAF démarre et
// sert avec la liste compilée sans attendre une dépendance externe. Un échec de
// récupération n'est pas une erreur de démarrage (FR-02).
func (u *Updater) Start(ctx context.Context) {
	go func() {
		u.refresh(ctx)

		ticker := time.NewTicker(u.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				u.refresh(ctx)
			}
		}
	}()
}

// refresh exécute un rafraîchissement et notifie les observateurs.
func (u *Updater) refresh(ctx context.Context) {
	count, err := u.Refresh(ctx)
	if err != nil {
		if u.onError != nil {
			u.onError(err)
		}
		return
	}
	if u.onSuccess != nil {
		u.onSuccess(count)
	}
}

// Refresh récupère les deux listes, les valide et — seulement si tout est
// valide — remplace la liste en vigueur. Retourne le nombre de préfixes adoptés.
//
// L'adoption est tout-ou-rien : une liste IPv6 illisible n'installe pas la seule
// liste IPv4, sans quoi un rafraîchissement partiel rétrécirait silencieusement
// la couverture (du trafic Cloudflare légitime commencerait à recevoir des 400).
func (u *Updater) Refresh(ctx context.Context) (int, error) {
	ipv4, err := u.fetchList(ctx, u.ipv4URL, true)
	if err != nil {
		return 0, fmt.Errorf("cloudflare ipv4 ranges: %w", err)
	}
	ipv6, err := u.fetchList(ctx, u.ipv6URL, false)
	if err != nil {
		return 0, fmt.Errorf("cloudflare ipv6 ranges: %w", err)
	}
	if err := validateFetchedRanges(ipv4, ipv6); err != nil {
		return 0, err
	}

	prefixes := make([]netip.Prefix, 0, len(ipv4)+len(ipv6))
	prefixes = append(prefixes, ipv4...)
	prefixes = append(prefixes, ipv6...)
	setRanges(prefixes)
	return len(prefixes), nil
}

// fetchList récupère et décode une liste. wantIPv4 dit quelle famille la source
// est censée publier : une liste v6 servie sur l'URL v4 est un signe que la
// réponse ne vient pas de la source attendue, donc un rejet.
func (u *Updater) fetchList(ctx context.Context, url string, wantIPv4 bool) ([]netip.Prefix, error) {
	if !u.allowInsecureSources && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("source %q must be https", url)
	}
	requestCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := u.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", response.StatusCode)
	}
	// LimitReader à maxPayloadBytes+1 : lire un octet de plus est ce qui permet
	// de DISTINGUER un corps exactement à la borne d'un corps tronqué.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPayloadBytes {
		return nil, fmt.Errorf("payload larger than %d bytes", maxPayloadBytes)
	}
	return parseRangeList(string(body), wantIPv4)
}

// parseRangeList décode une liste de préfixes CIDR, un par ligne. Toute ligne
// non conforme fait échouer la liste entière : une page d'erreur HTML ou un
// portail captif ne doit pas produire une liste « partiellement lue ».
func parseRangeList(body string, wantIPv4 bool) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, 32)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q", line)
		}
		if prefix.Addr().Is4() != wantIPv4 {
			return nil, fmt.Errorf("prefix %q does not belong to the expected address family", line)
		}
		// Un préfixe non canonique (bits d'hôte posés) signale une liste
		// bricolée ; l'accepter reviendrait à faire confiance à la
		// normalisation de netip pour une frontière de sécurité.
		if prefix.Masked() != prefix {
			return nil, fmt.Errorf("prefix %q is not canonical", line)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, errors.New("no prefix found")
	}
	return prefixes, nil
}

// validateFetchedRanges refuse une liste qui élargirait la confiance au-delà du
// plausible. C'est la garde de sécurité du rafraîchissement : la liste décide
// quelles sources peuvent poser CF-Connecting-IP, donc quelle IP le WAF croit
// pour toutes ses décisions ensuite (score, rate limiting, blacklist).
func validateFetchedRanges(ipv4 []netip.Prefix, ipv6 []netip.Prefix) error {
	if len(ipv4) < minPrefixesPerFamily {
		return fmt.Errorf("ipv4 list has %d prefixes, want at least %d", len(ipv4), minPrefixesPerFamily)
	}
	if len(ipv6) < minPrefixesPerFamily {
		return fmt.Errorf("ipv6 list has %d prefixes, want at least %d", len(ipv6), minPrefixesPerFamily)
	}
	if total := len(ipv4) + len(ipv6); total > maxPrefixesTotal {
		return fmt.Errorf("fetched list has %d prefixes, want at most %d", total, maxPrefixesTotal)
	}
	for _, prefix := range ipv4 {
		if prefix.Bits() < minIPv4PrefixLen {
			return fmt.Errorf("ipv4 prefix %s is wider than /%d", prefix, minIPv4PrefixLen)
		}
	}
	for _, prefix := range ipv6 {
		if prefix.Bits() < minIPv6PrefixLen {
			return fmt.Errorf("ipv6 prefix %s is wider than /%d", prefix, minIPv6PrefixLen)
		}
	}
	return nil
}
