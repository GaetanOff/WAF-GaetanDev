// Package web embarque les pages servies par le WAF dans le binaire : il doit
// démarrer quel que soit son répertoire de travail (binaire unique autonome,
// objectif G7 de specs/mission.md).
package web

import _ "embed"

// ChallengePage est le template de la page de challenge JS (FR-04).
//
//go:embed challenge.html
var ChallengePage string
