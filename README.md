# Envoy-kubeWAF 🛡️

A Kubernetes-native Security Engine (WAF) designed to sit behind **Envoy Proxy/Gateway** using the `ext_authz` filter for high-performance traffic filtering.

> [!IMPORTANT]
> **Project Status: Homelab & Learning Lab**
> This is a hobby project built specifically to secure my exposed personal services. I am using this as a "living laboratory" to deepen my expertise in **Cloud Native Security**, **Envoy architecture**, and **asynchronous Python** at scale. Expect frequent updates as I experiment with new security modules.

## The Vision

I built this because existing WAF solutions were either too heavy for a small homelab or lacked the granular control I wanted for specific traffic patterns. This project bridges the gap between a simple reverse proxy and an enterprise-grade WAF.

## Features

* **GeoIP Blocking** – Precise country-based filtering using MaxMind GeoLite2 (with background auto-reload).
* **Bot Detection** – Proactive blocking of 35+ known scanners and bad actors (e.g., `sqlmap`, `nikto`).
* **Cloud-Native Integration** – Native `ext_authz` support for Envoy Gateway and Istio.
* **Async Engine** – Built on FastAPI for sub-millisecond authorization decisions.
* **Modular Architecture** – Easily pluggable `BaseSecurityModule` interface for adding custom logic.

## Architecture

The request flow follows a **Sidecar/External Auth** pattern:
`Client` → `Envoy` → `KubeWAF` (Decision) → `Envoy` → `Your Service`

## Quick Start

### 1. Configure Environment

```bash
cp .env.example .env
# Add your MaxMind License Key to .env

```

### 2. Local Development (Docker)

This runs the Security Engine alongside the automated GeoIP updater.

```bash
mkdir geoip_db
docker compose up -d

```

### 3. Kubernetes Deployment

```bash
# Deploy the full stack
kubectl -k k8s/ -n kubewaf

# Manually trigger the initial GeoIP database download
kubectl create job --from=cronjob/geoip-db-updater geoip-db-initial-manual -n kubewaf

```

## Roadmap & Future Features

* [ ] **JWT Validation:** Inspecting OIDC tokens at the edge.
* [ ] **Prometheus Metrics:** Grafana dashboards for "Blocked vs Allowed" traffic.
* [ ] **IP Intelligence:** Integration with CrowdSec or AbuseIPDB feeds.

## Endpoints

* `GET /` – The main authorization hook called by Envoy.
* `GET /health/security` – Real-time status of loaded modules and GeoIP health.
* `GET /captures` – Debug endpoint to inspect headers and metadata sent by Envoy.

---
