package cloudflare

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const connectingIPHeader = "Cf-Connecting-Ip" // CF-Connecting-IP, forme canonique

// infrastructureHeaderPrefix est le préfixe des en-têtes posés par Cloudflare
// (CF-IPCountry, CF-Ray, Cf-Bot-Management-Ja3Hash…), comparé sans casse.
const infrastructureHeaderPrefix = "CF-"

type realIPContextKey struct{}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceIP, err := remoteIP(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid remote address", http.StatusBadRequest)
			return
		}

		connectingIP := r.Header.Get(connectingIPHeader)
		fromCloudflare := IsCloudflareIP(sourceIP)
		if connectingIP != "" && !fromCloudflare {
			http.Error(w, "forged CF-Connecting-IP header", http.StatusBadRequest)
			return
		}
		if !fromCloudflare {
			// ADR-019 option B : un CF-* ne vaut que s'il vient de Cloudflare.
			stripInfrastructureHeaders(r.Header)
			next.ServeHTTP(w, withRealIP(r, sourceIP.String()))
			return
		}
		if connectingIP == "" {
			next.ServeHTTP(w, withRealIP(r, sourceIP.String()))
			return
		}

		realIP, err := netip.ParseAddr(connectingIP)
		if err != nil {
			http.Error(w, "invalid CF-Connecting-IP header", http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, withRealIP(r, realIP.String()))
	})
}

// StripUntrusted supprime tout en-tête CF-* de la requête. Monté à la place de
// Middleware quand cloudflare.trusted est faux : le WAF ne reconnaît alors
// aucun intermédiaire Cloudflare, donc aucun CF-* n'a d'origine prouvable
// (ADR-019 option B).
func StripUntrusted(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripInfrastructureHeaders(r.Header)
		next.ServeHTTP(w, r)
	})
}

// stripInfrastructureHeaders aligne la forge d'un CF-* sur son omission :
// CF-IPCountry (géo, règles) ou Cf-Bot-Management-Ja3Hash (blacklist JA3)
// forgés par un client qui joint le WAF hors Cloudflare se comportent comme
// absents — chemin déjà spécifié (dégradation gracieuse) et testé. Cela ne
// ferme PAS le contournement par omission : seul un rejet des connexions hors
// intermédiaire de confiance le ferait (ADR-019 option D).
func stripInfrastructureHeaders(header http.Header) {
	for name := range header {
		if len(name) >= len(infrastructureHeaderPrefix) && strings.EqualFold(name[:len(infrastructureHeaderPrefix)], infrastructureHeaderPrefix) {
			delete(header, name)
		}
	}
}

func RealIP(r *http.Request) string {
	if value, ok := r.Context().Value(realIPContextKey{}).(string); ok && value != "" {
		return value
	}

	ip, err := remoteIP(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip.String()
}

func IsCloudflareIP(ip netip.Addr) bool {
	for _, prefix := range Ranges() {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func withRealIP(r *http.Request, ip string) *http.Request {
	ctx := context.WithValue(r.Context(), realIPContextKey{}, ip)
	return r.WithContext(ctx)
}

func remoteIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return netip.ParseAddr(host)
}
