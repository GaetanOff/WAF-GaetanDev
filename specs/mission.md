---
status: approved
version: 1.0.0
last-reviewed: 2026-06-03
---

# Mission — WAF Anti-DDoS / Anti-Bot

## Problem Statement

Sites web exposés directement sur Internet subissent des attaques DDoS volumétriques, du scraping automatisé, des tentatives de brute-force et du trafic bot qui dégradent les performances, augmentent les coûts d'infrastructure et compromettent la sécurité. Les solutions existantes (Cloudflare seul, fail2ban, nginx rate-limit) ne fournissent pas de couche applicative intelligente capable de distinguer un humain d'un bot sans imposer de friction (CAPTCHA).

## Mission

Construire un reverse proxy WAF écrit en Go, hautement performant, qui s'intercale entre Cloudflare et le serveur d'origine. Il analyse chaque requête entrante, attribue un score de confiance au visiteur, bloque ou challenge les comportements suspects, et laisse passer le trafic légitime de manière transparente — sans CAPTCHA, sans friction notable pour l'utilisateur humain.

## Goals

| ID | Goal |
|----|------|
| G1 | Bloquer les attaques DDoS volumétriques avant qu'elles atteignent l'origine |
| G2 | Détecter et bloquer les bots sans friction utilisateur (zéro CAPTCHA) |
| G3 | Valider silencieusement les navigateurs humains via un challenge JavaScript |
| G4 | Maintenir une latence ajoutée < 5 ms pour les requêtes en cache de session |
| G5 | Supporter une configuration par domaine, flexible et dynamique |
| G6 | Fournir une observabilité complète via logs structurés et métriques Prometheus |
| G7 | Être déployable en production sur un seul binaire Go avec configuration YAML |

## Success Metrics

| Métrique | Cible |
|----------|-------|
| Latence P99 ajoutée (visiteur connu) | < 5 ms |
| Latence challenge JS (ressenti utilisateur) | < 3 secondes |
| Taux de faux positifs (humains bloqués) | < 0.1 % |
| Taux de détection bots connus | > 99 % |
| Débit maximum supporté | > 50 000 req/s (single node) |
| Disponibilité cible | 99.9 % |

## Non-Goals

- Pas de CAPTCHA, pas de reCAPTCHA, pas de hCaptcha
- Pas d'interface d'administration graphique (v1)
- Pas de DPI (deep packet inspection) au niveau TCP/IP
- Pas de protection contre les injections SQL / XSS (responsabilité de l'application)
- Pas de CDN intégré

## Constraints

- Développé en Go 1.26+
- Doit fonctionner derrière Cloudflare (extraction IP réelle via `CF-Connecting-IP`)
- Binaire unique, pas de dépendances runtime obligatoires (Redis optionnel)
- Configuration YAML versionnable en Git
- Compatible Linux AMD64 / ARM64

## Actors

| Acteur | Rôle |
|--------|------|
| Visiteur humain | Navigue sur le site — ne doit pas être bloqué |
| Bot légitime | Googlebot, indexeurs — configurables en whitelist |
| Bot malveillant | Scrapers, DDoS bots — doit être bloqué ou challengé |
| Attaquant DDoS | Envoie des volumes massifs de requêtes |
| Administrateur | Configure et supervise le WAF |
| Cloudflare | Proxy amont, fournit l'IP réelle et des headers de contexte |
