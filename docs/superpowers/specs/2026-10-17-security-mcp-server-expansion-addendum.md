# Security MCP Server — Expansion Addendum

**Date:** 2026-10-17
**Status:** Approved
**Extends:** `docs/superpowers/specs/2026-10-17-security-mcp-server-design.md`

## Goal

Add two read-only tools (`check_domain`, `check_hash`) and eleven providers to
the existing three-tool server, and enrich the existing tools with reverse-DNS,
passive-DNS, passive open-port/service, EPSS and CISA-KEV data.

## Interview Decisions (locked)

| # | Decision |
|---|----------|
| E1 | New tools: `check_domain` (type `domain`) and `check_hash` (type `hash`) |
| E2 | Recon folded into existing tools; no separate `check_hostname` tool |
| E3 | Open ports / running services are **passive only** (Shodan InternetDB); **no active scanning** |
| E4 | OS version is **dropped** (no keyless passive source; active fingerprinting forbidden) |
| E5 | Reverse lookup for an IP = `reverse_dns` (PTR) + `otx_ip` passive-DNS hostnames |
| E6 | Reverse lookup for a domain = `otx_domain` passive-DNS IPs |
| E7 | Read-only guarantee unchanged: every outbound call is an HTTP GET |

## Tools

| Tool | Input | type | Validation |
|------|-------|------|------------|
| `check_ip` | `ip`, `providers` | `ip` | `ipaddress.ip_address` (unchanged) |
| `check_url` | `url`, `providers` | `url` | unchanged |
| `lookup_cve` | `cve_id`, `providers` | `cve` | unchanged |
| `check_domain` | `domain`, `providers` | `domain` | `validate_domain` |
| `check_hash` | `file_hash`, `providers` | `hash` | `validate_hash` |

Output shape is identical to the existing tools. `type` is `domain` / `hash`
for the two new tools.

### Validators

- `validate_domain(value) -> str`: `value.strip().lower().rstrip(".")`; reject
  empty, scheme/`/`/`:`/`\`/space, `localhost`, `.local`/`.internal`, IP
  literals, missing dot, total length >253, any label empty or >63 chars; every
  label must match `^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`. Return normalized.
- `validate_hash(value) -> str`: `value.strip().lower()`; must match
  `^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$` (md5/sha1/sha256).

## New Providers

| Provider | Tool | Endpoint (GET) | Auth | Keyless |
|----------|------|----------------|------|---------|
| `rdap` | domain | `https://rdap.org/domain/{d}` | no | yes |
| `dns` | domain | `https://dns.google/resolve?name={d}&type={A,MX,NS,TXT}` | no | yes |
| `crtsh` | domain | `https://crt.sh/?q=%25.{d}&output=json` | no | yes |
| `otx_domain` | domain | `https://otx.alienvault.com/api/v1/indicators/domain/{d}/general` + `/passive_dns` | no | yes |
| `ipinfo` | ip | `https://ipinfo.io/{ip}/json` | optional `token` query (`IPINFO_TOKEN`) | yes |
| `internetdb` | ip | `https://internetdb.shodan.io/{ip}` | no | yes |
| `reverse_dns` | ip | `https://dns.google/resolve?name={reverse_pointer}&type=PTR` | no | yes |
| `otx_ip` | ip | `https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general` + `/passive_dns` | no | yes |
| `epss` | cve | `https://api.first.org/data/v1/epss?cve={id}` | no | yes |
| `cisa_kev` | cve | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | no | yes |
| `circl` | cve | `https://cve.circl.lu/api/cve/{id}` | no | yes |
| `virustotal_file` | hash | `https://www.virustotal.com/api/v3/files/{hash}` | `x-apikey` (`VT_API_KEY`) | no |
| `otx_file` | hash | `https://otx.alienvault.com/api/v1/indicators/file/{hash}/general` | no | yes |

`rdap` follows the bootstrap redirect (`follow_redirects=True` on that one
request only; still GET). `reverse_dns` builds the PTR name with
`ipaddress.ip_address(value).reverse_pointer` (handles IPv4 and IPv6).

### Normalization rules

- **rdap:** registration data is not itself a threat signal → `benign`/`none`;
  a domain registered <30 days ago → `suspicious`/`medium`. data: `registrar,
  created, expires, updated, statuses, nameservers, dnssec, age_days`. 404 →
  `not_found`.
- **dns:** `benign`/`none`; data: `a, mx, ns, txt` (each ≤10 entries).
- **crtsh:** `benign`/`none`; data: `subdomain_count, subdomains` (≤50 unique,
  sorted).
- **otx_domain / otx_ip / otx_file:** pulse count >0 → `suspicious`/`medium`,
  else `benign`/`none`. `otx_domain` data adds `passive_dns_ips` (≤10);
  `otx_ip` data adds `passive_dns_hostnames` (≤10); `otx_file` data adds
  `validation, detection_count`.
- **ipinfo:** `benign`/`none`; data: `city, region, country, org, loc, timezone`.
- **internetdb:** verdict `unknown`; severity `medium` if any `vulns`, else
  `none`; data: `ports, tags, hostnames, cpes` (≤10), `vulns_count, vulns`
  (≤10). 404 → `not_found`. (Passive snapshot; weekly refresh; no banners.)
- **reverse_dns:** `benign`/`none`; data: `ptr` (≤10).
- **epss:** verdict `unknown`; severity: `epss>=0.5` → `medium`,
  `>=0.1` → `low`, else `none`; data: `epss, percentile, date`. No data →
  `not_found`.
- **cisa_kev:** CVE present in catalog → `malicious`/`high`, else
  `benign`/`none`; data: `listed, dateAdded, dueDate,
  knownRansomwareCampaignUse, requiredAction, vendorProject, product`.
- **circl:** CVSS via `from_cvss`; data: `cvss, vector, summary` (≤500),
  `references` (≤5), `published`. 404/empty → `not_found`.
- **virustotal_file:** `last_analysis_stats.malicious>0` → `malicious`/`high`;
  `suspicious>0` → `suspicious`/`medium`; else `benign`/`none`; data: `mal,
  sus, reputation, meaningful_name, type_description`. 404 → `not_found`.

### Rates (tokens/sec, self-imposed)

ipinfo 1.0, internetdb 5.0, reverse_dns 5.0, otx_ip 0.5, rdap 1.0, dns 5.0,
crtsh 0.5, otx_domain 0.5, epss 1.0, cisa_kev 0.1, circl 0.5,
virustotal_file 0.15, otx_file 0.5.

## New core module

`core/feed.py` — `FeedCache(ttl, clock=time.monotonic)` with
`async get(fetcher) -> value`: single-entry, long-TTL, lock-guarded cache so
concurrent CVE lookups share one feed download. Used by `cisa_kev`
(ttl 21600s).

## Security constraints (unchanged, restated)

- Only `httpx.get`; no POST/PUT/PATCH/DELETE; no scan submission.
- Keys from env only, never logged (secret values redacted from errors).
- One provider failure never fails the call.
- **No active scanning / no OS fingerprinting** (E3, E4).
