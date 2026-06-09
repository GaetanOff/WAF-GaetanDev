// Package tlsfp gère le fingerprinting TLS / JA3 (FR-11). En déploiement
// derrière Cloudflare (mode principal), le hash JA3 est lu depuis le header
// Cf-Bot-Management-Ja3Hash. Le calcul JA3 à partir d'un ClientHello (mode TLS
// direct) est fourni comme utilitaire pur ; son câblage live est différé.
package tlsfp

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3String construit la chaîne JA3 canonique :
// SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// (champs séparés par des virgules, valeurs par des tirets).
func JA3String(version uint16, ciphers []uint16, extensions []uint16, curves []uint16, pointFormats []uint8) string {
	parts := []string{
		strconv.Itoa(int(version)),
		joinUint16(ciphers),
		joinUint16(extensions),
		joinUint16(curves),
		joinUint8(pointFormats),
	}
	return strings.Join(parts, ",")
}

// JA3Hash retourne le MD5 hexadécimal d'une chaîne JA3 (le hash JA3 standard).
//
// MD5 est imposé par la spécification JA3 : le hash est un identifiant de
// fingerprint (bucketing / corrélation), pas une signature de sécurité, et
// doit rester du MD5 pour rester interopérable avec les feeds de threat
// intelligence qui publient des hashes JA3 en MD5. La résistance aux
// collisions n'est pas un objectif ici, et l'entrée n'est pas un secret.
// Remplacer MD5 par SHA-256 casserait toute comparaison avec ja3_blacklist.
func JA3Hash(ja3 string) string {
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

func joinUint16(values []uint16) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strconv.Itoa(int(v))
	}
	return strings.Join(out, "-")
}

func joinUint8(values []uint8) string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strconv.Itoa(int(v))
	}
	return strings.Join(out, "-")
}
