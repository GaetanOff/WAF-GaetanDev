// G6 — test de charge nominal du WAF (specs/validation.md, SLO de NFR-01/02).
//
// Mesure la latence de bout en bout d'un visiteur connu à travers tout le
// pipeline. Pour que la mesure reflète le coût du WAF et non celui de
// l'origine, lancer le WAF devant une origine locale triviale, challenge JS
// désactivé (ou IP de charge en whitelist) et rate limit relevé :
//
//   WAF_URL=http://127.0.0.1:8080 k6 run tests/load/basic.js
//   make perf
//
// Variables : WAF_URL (défaut http://127.0.0.1:8080), WAF_HOST (en-tête Host,
// défaut example.com), VUS (défaut 100), DURATION (défaut 5m).
import http from "k6/http";
import { check } from "k6";

const target = __ENV.WAF_URL || "http://127.0.0.1:8080";
const host = __ENV.WAF_HOST || "example.com";

export const options = {
  scenarios: {
    known_visitors: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 100),
      duration: __ENV.DURATION || "5m",
    },
  },
  // SLO de validation.md (visiteur connu) : P50 < 1 ms, P99 < 5 ms. Seules
  // les réponses servies (200) comptent : un 429 est une décision, pas une
  // latence de pipeline.
  thresholds: {
    "http_req_duration{expected_response:true}": ["p(50)<1", "p(99)<5"],
    checks: ["rate>0.99"],
  },
};

export default function () {
  const response = http.get(`${target}/`, {
    headers: {
      Host: host,
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) k6-load-test",
      Accept: "text/html",
      "Accept-Language": "fr-FR,fr;q=0.9",
      "Accept-Encoding": "gzip",
    },
  });
  check(response, {
    "served (200)": (r) => r.status === 200,
  });
}
