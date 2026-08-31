// Package jsonstrict décode le JSON provenant d'une source non fiable (corps de
// requête client, réponse d'une API tierce) avec des garde-fous plus stricts que
// encoding/json v1.
//
// Motivation : v1 accepte les noms de membre dupliqués et applique la règle
// « le dernier gagne ». Un WAF qui lit "b" dans {"k":"a","k":"b"} alors que
// l'origine lit "a" offre un différentiel de parseur — un vecteur classique de
// contournement. v1 accepte également l'UTF-8 invalide et le remplace
// silencieusement par U+FFFD, ce qui altère la valeur inspectée.
//
// encoding/json/v2 (Go 1.27) rejette ces deux cas. Les deux options ci-dessous
// restaurent par ailleurs les comportements v1 sur lesquels le code s'appuie,
// pour que le seul changement observable soit le rejet de JSON ambigu ou mal
// formé :
//
//   - RejectUnknownMembers      équivalent de Decoder.DisallowUnknownFields
//   - MatchCaseInsensitiveNames v1 apparie les noms sans tenir compte de la
//     casse ; v2 exige une correspondance exacte par défaut
package jsonstrict

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
)

var opts = json.JoinOptions(
	json.RejectUnknownMembers(true),
	json.MatchCaseInsensitiveNames(true),
)

// Decode lit exactement une valeur JSON depuis r et la décode dans out.
//
// Comme json.Decoder.Decode (v1) et contrairement à json.UnmarshalRead, Decode
// ne lit pas jusqu'à EOF : le contenu qui suit la première valeur est ignoré.
// C'est ce qui permet de l'utiliser sur un corps de requête non borné sans
// transformer une requête volumineuse en lecture intégrale.
func Decode(r io.Reader, out any) error {
	return json.UnmarshalDecode(jsontext.NewDecoder(r), out, opts)
}

// Unmarshal décode une valeur JSON déjà en mémoire, avec les mêmes garde-fous
// que Decode.
func Unmarshal(data []byte, out any) error {
	return json.Unmarshal(data, out, opts)
}
