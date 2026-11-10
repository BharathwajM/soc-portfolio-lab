"""Enrich IP addresses with free threat-intel sources that need no API key.

    python scripts/enrich_ips.py --out evidence/honeypot-ip-enrichment.json \
        78.46.176.17=brute-force 216.25.90.11=scanner ...

For each IP it asks:
  RIPEstat         network owner (ASN), announced prefix, registry country, abuse contact
  GreyNoise        whether the IP is seen mass-scanning the internet, and what it is (community API)
  Shodan InternetDB  open ports, tags and hostnames seen by Shodan

Results describe each IP on the day of the lookup, not on the day of the attack.
Standard library only. The only data sent out is the IP addresses themselves.
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request

HEADERS = {"User-Agent": "soc-portfolio-lab-enrichment", "Accept": "application/json"}


def get_json(url: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:  # 404 means "nothing known" for GreyNoise and InternetDB
        try:
            return e.code, json.load(e)
        except ValueError:
            return e.code, {}


def ripestat(call: str, ip: str) -> dict:
    url = f"https://stat.ripe.net/data/{call}/data.json?" + urllib.parse.urlencode({"resource": ip})
    return get_json(url)[1].get("data", {})


def enrich(ip: str, role: str) -> dict:
    prefix = ripestat("prefix-overview", ip)
    geo = ripestat("rir-geo", ip).get("located_resources", [])
    abuse = ripestat("abuse-contact-finder", ip).get("abuse_contacts", [])
    gn_status, gn = get_json(f"https://api.greynoise.io/v3/community/{ip}")
    sh_status, sh = get_json(f"https://internetdb.shodan.io/{ip}")
    asns = prefix.get("asns", [])
    return {
        "ip": ip,
        "role": role,
        "asn": asns[0]["asn"] if asns else None,
        "as_holder": asns[0]["holder"] if asns else None,
        "prefix": prefix.get("resource"),
        "registry_country": geo[0]["location"] if geo else None,
        "abuse_contact": abuse[0] if abuse else None,
        "greynoise": {
            "http_status": gn_status,
            "noise": gn.get("noise"),          # seen mass-scanning the internet
            "riot": gn.get("riot"),            # known benign business service
            "classification": gn.get("classification"),
            "name": gn.get("name"),
            "last_seen": gn.get("last_seen"),
            "message": gn.get("message"),
        },
        "shodan_internetdb": {
            "http_status": sh_status,
            "ports": sh.get("ports", []),
            "tags": sh.get("tags", []),
            "hostnames": sh.get("hostnames", []),
            "known_vulns": len(sh.get("vulns", [])),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("targets", nargs="+", help="IP or IP=role, for example 78.46.176.17=brute-force")
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between IPs, to respect rate limits")
    args = ap.parse_args()
    results = []
    for i, t in enumerate(args.targets):
        ip, _, role = t.partition("=")
        if i:
            time.sleep(args.delay)
        results.append(enrich(ip, role or "unknown"))
        r = results[-1]
        print(f"{ip:16} AS{r['asn']} {r['as_holder']} | {r['registry_country']} | "
              f"GreyNoise noise={r['greynoise']['noise']} {r['greynoise']['classification']} | "
              f"ports={r['shodan_internetdb']['ports']}")
    doc = {"queried_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "sources": ["RIPEstat", "GreyNoise Community API", "Shodan InternetDB"],
           "results": results}
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
