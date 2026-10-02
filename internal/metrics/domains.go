package metrics

import "github.com/gaetandev/waf/internal/hostname"

// undeclaredDomain est le label domain de tout hôte absent de domains[]. Le
// label reprenait r.Host : sans server.strict_host, chaque Host inventé par un
// client créait une série Prometheus, conservée jusqu'à l'arrêt du processus —
// une croissance mémoire pilotée par l'attaquant.
const undeclaredDomain = hostname.Undeclared

// globalScope est la portée du mode « sous attaque » quand il n'est pas suivi
// par domaine (antiddos.UnderAttackDetector).
const globalScope = "*"
