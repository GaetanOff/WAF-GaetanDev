// Package httpbody draine les corps de réponse des clients HTTP sortants du WAF
// (sondes d'upstream, webhooks, réputation IP, plages Cloudflare) pour
// préserver la réutilisation des connexions.
package httpbody

import "io"

// maxDrainBytes borne la lecture du reliquat : au-delà, recycler la connexion
// coûte plus cher que d'en ouvrir une neuve, et un pair hostile ne doit pas
// pouvoir faire lire indéfiniment le WAF.
const maxDrainBytes = 64 << 10

// Drain lit le reliquat du corps (borné), à appeler juste avant Body.Close.
// Le transport net/http ne remet une connexion keep-alive dans le pool que si
// son corps a été lu jusqu'à EOF : fermé sans être drainé, il ferme la
// connexion TCP, et chaque sonde ou webhook en rouvrait une (handshake TLS
// compris).
func Drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxDrainBytes))
}
