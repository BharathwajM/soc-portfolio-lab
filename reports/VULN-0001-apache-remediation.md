# VULN-0001: Outdated Apache HTTP Server, scan, fix and verify

> **LAB EXERCISE.** The target is a deliberately outdated Apache container on an isolated Docker network (`soc-openvas-targets`, `internal=true`, no host ports). Only the scanner and the target are attached to it.

| Field | Value |
|---|---|
| Scanner | Greenbone Community Edition (OpenVAS), feed 202611070548, scan config *Full and fast* |
| Target | `172.31.250.10`, TCP 80 only (port list "SOC lab TCP 80 only") |
| Baseline | `httpd:2.4.49`, report `0cf2c7bb-103e-43da-bd18-231fc98589e5`, finished 2026-11-07 10:09 UTC |
| Patched | `httpd:2.4` → Apache 2.4.69, report `93e9a8e4-4a4c-43a9-88f5-87bb81f02c32`, finished 2026-11-07 10:16 UTC |
| Hardened | Apache 2.4.69 + `TraceEnable Off`, report `a085a779-bf6b-45ec-a2e8-c3105153b364`, finished 2026-11-07 10:23 UTC |
| Evidence | `evidence/openvas-baseline.json`, `evidence/openvas-patched.json`, `evidence/openvas-hardened.json` |

## 1. Results at a glance

| Severity (CVSS) | Baseline 2.4.49 | Patched 2.4.69 | Hardened |
|---|---|---|---|
| High (7.0–10) | 4 | 0 | 0 |
| Medium (4.0–6.9) | 9 | 1 (TRACE) | 0 |
| Low (0.1–3.9) | 3 | 2 | 2 |
| Log / info | 12 | 12 | 12 |
| **Total results** | **28** | **15** | **14** |
| Apache version CVE findings | 13 (18 CVEs) | 0 | 0 |

## 2. Baseline findings (Apache 2.4.49)

| CVSS | Finding | CVEs |
|---|---|---|
| 8.2 | Apache 2.4.7 – 2.4.51 Multiple Vulnerabilities | CVE-2021-44224 |
| 7.5 | 2.4.30 – 2.4.55 HTTP Request Smuggling | CVE-2023-27522 |
| 7.5 | < 2.4.58 `mod_macro` Out-of-bounds Read | CVE-2023-31122 |
| 7.5 | < 2.4.59 Multiple Vulnerabilities | CVE-2023-38709, CVE-2024-24795, CVE-2024-27316 |
| 5.9 | 2.4.17 – 2.4.57 DoS | CVE-2023-45802 |
| 5.8 | 2.4.7 – 2.4.65 Authentication Bypass | CVE-2025-66200 |
| 5.8 | HTTP Debugging Methods (TRACE/TRACK) Enabled | (configuration) |
| 5.0 | < 2.4.64 DoS ×2, Access Control Bypass, Multiple Vulnerabilities | CVE-2025-53020, CVE-2025-49630, CVE-2025-23048, CVE-2024-42516, CVE-2024-43204, CVE-2024-47252, CVE-2025-49812 |
| 4.3 | < 2.4.66 Improper Neutralization, SSI | CVE-2025-65082, CVE-2025-58098 |
| 2.6 | 2.4.30 – 2.4.65 Integer Overflow | CVE-2025-55753 |
| 2.6 / 2.1 | TCP timestamps, ICMP timestamp reply | CVE-1999-0524 |

**Quality of detection.** The Apache findings have QoD 30%. They are version checks against the server banner, and OpenVAS can't confirm the distribution build from outside, so it marks them as less certain. The banner reported exactly 2.4.49, and `httpd -v` inside the container confirmed it. The TRACE finding has QoD 99% because the scanner actually sent a TRACE request and got it echoed back.

**CVE-2021-41773 and CVE-2021-42013 were not reported.** These are the well-known path traversal and RCE bugs specific to 2.4.49/2.4.50. OpenVAS tests them by actually attempting the traversal. The stock `httpd.conf` in the official image protects the filesystem root with `<Directory /> Require all denied`, and `mod_cgi` is off. Apache's advisory says the attack only works when that protection is missing, so the active check failed and nothing was reported. A version-only scanner would have flagged it. The takeaway: an empty result for a famous CVE doesn't mean the version is safe. The upgrade is still required.

## 3. Remediation

1. **Upgrade.** Replace `httpd:2.4.49` with the current `httpd:2.4` image (Apache **2.4.69**). Same IP, port, port list and scan config.
2. **Rescan.** All 13 Apache version findings (18 CVEs) are gone. Nothing new appeared.
3. **Residual: TRACE enabled (5.8, medium).** This is a configuration setting, so the upgrade doesn't change it. TRACE can help cross-site tracing (XST) attacks reflect headers such as cookies. Fix: add `TraceEnable Off` to `httpd.conf`.
4. **Rescan after hardening.** The TRACE finding is gone. The final scan has **0 high and 0 medium** findings. The only items left are two low-severity network notes (TCP and ICMP timestamps), accepted below.

## 4. Accepted residual items

| Finding | Severity | Decision |
|---|---|---|
| TCP timestamps information disclosure | 2.6 | Accept. Low risk; it reveals uptime. Change only via host sysctl if policy requires it. |
| ICMP timestamp reply | 2.1 | Accept on an isolated lab network; block ICMP types 13/14 at the perimeter in production. |
| Log / info items (banner, OS detection, security headers) | 0.0 | Informational. In production, also set `ServerTokens Prod` and add security headers. |

## 5. Lessons

- A version upgrade fixed every CVE finding, but configuration problems such as TRACE survive upgrades and need their own fix.
- Rescan with the *same* target, port list and scan config, or the before-and-after comparison doesn't mean anything.
- Check that the scanner can actually reach the target before trusting a clean report. The first baseline attempt came back almost empty because the target container had stopped. A reachability check now runs before every scan.
