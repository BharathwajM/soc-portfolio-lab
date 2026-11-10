# Honeypot IP enrichment (looked up 2026-11-10, 09:28 UTC)

I looked up the 15 IP addresses named in the honeypot evidence with [`scripts/enrich_ips.py`](../scripts/enrich_ips.py), using three free sources that need no API key:

- **RIPEstat**: who owns the network, the registry country and the abuse contact
- **GreyNoise Community**: whether the IP is seen mass-scanning the internet, and whether that scanning is known to be benign
- **Shodan InternetDB**: open ports and tags Shodan has recorded

Raw results: [`honeypot-ip-enrichment.json`](honeypot-ip-enrichment.json). The honeypot ran on 2026-11-07, so these lookups describe each IP three days later. Cloud and hosting addresses in particular can change hands.

## The two IPs that tried passwords

| IP | Attempts | Network | GreyNoise | Shodan | Reading |
|---|---|---|---|---|---|
| 78.46.176.17 | 4,471 | Hetzner Online (AS24940), Germany, hosting | **Not seen scanning** | No data | A rented server that did not sweep the internet, yet ran a 6-hour password attack on this one host. That suggests it was working from a target list, possibly built from earlier scans. |
| 175.203.62.5 | 2 (`Test`) | Korea Telecom (AS4766), South Korea, ISP | **Malicious**, last seen 2026-11-09 | 31 open ports including RDP 3389, tagged end-of-life product, 303 known CVEs | Looks like a compromised machine on a home or business connection being used to attack others |

## The 13 scanners that connected without sending a password

| IP | Network | GreyNoise | Note |
|---|---|---|---|
| 216.25.90.11, 198.235.24.79 | Google Cloud, abuse contact Palo Alto Networks | Benign: **Cortex Xpanse** | Attack-surface scanner. 216.25.90.11 was the first connection Sentinel recorded (16:38). |
| 194.187.178.28, .74, .90, .163, .203, .235 | Alpha Strike Labs (AS215778), Germany | Benign: **Alpha Strike Labs** | The burst of 6 connections at 18:36:21 |
| 194.180.49.36 | Mevspace (AS201814), registered in Bulgaria | **Malicious** | Connected at 17:39:43, about 4 seconds after the brute force from 78.46.176.17 began. The timing is close, but the data cannot show the two are linked. |
| 82.147.85.101 | VPS provider (AS211860), Russia | **Suspicious**, Shodan tag `scanner` | |
| 35.206.146.145 | Google Cloud (AS15169) | **Malicious** | |
| 199.165.159.121 | The Shadowserver Foundation (AS22168) | **Malicious** | Shadowserver is a non-profit that scans the internet and reports exposed services to network owners. A "malicious" label from one feed does not make a source an adversary. |
| 4.247.144.80 | Microsoft Azure (AS8075) | Not seen | Another cloud tenant. Not enough data to judge. |

Summary: GreyNoise rates 8 of the 13 scanners as known benign research or attack-surface scanners, 4 as malicious and 1 as suspicious. It has not seen the main attacker scanning at all.

## What this changes in triage

- **Blocking by reputation alone would have missed the main attacker.** 78.46.176.17 had no bad reputation in GreyNoise or Shodan. The behaviour (4,471 failures over 6 hours) is what identified it, which is why the Sentinel rules key on behaviour.
- **Known benign scanners can be lower priority.** Cortex Xpanse and Alpha Strike Labs only connected. In a busy queue, a GreyNoise "benign" result on a connect-only source is a reasonable reason to deprioritise it, though not to stop collecting it.
- **Reputation needs context.** Shadowserver's "malicious" label shows why an analyst should check who owns an address before acting on a tag.
- **Abuse reporting.** RIPEstat gives the abuse contact for each network (for example, Hetzner for 78.46.176.17). In a real incident, an abuse report with timestamps and log extracts is the usual next step for a hosting-provider source. I did not send any reports from this lab.

## Reproduce

```bash
python scripts/enrich_ips.py --out evidence/honeypot-ip-enrichment.json \
    78.46.176.17=brute-force 175.203.62.5=brute-force 216.25.90.11=scanner ...
```

The script uses only the Python standard library and sends nothing but the IP addresses. GreyNoise's community API is rate-limited, so the script waits 2 seconds between IPs.
