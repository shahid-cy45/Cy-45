#!/usr/bin/env python3
"""Simple child-safety firewall for filtering unsafe video/image content."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


@dataclass
class FirewallDecision:
    allowed: bool
    reason: str


DEFAULT_RULES = {
    "safe_domains": [
        "kids.youtube.com",
        "pbskids.org",
        "nationalgeographic.com",
        "khanacademy.org",
    ],
    "blocked_domains": [
        "pornhub.com",
        "xvideos.com",
        "redtube.com",
        "xnxx.com",
        "xhamster.com",
    ],
    "blocked_keywords": [
        "adult",
        "porn",
        "xxx",
        "nude",
        "naked",
        "sex",
        "escort",
        "18+",
        "nsfw",
        "camgirl",
        "hardcore",
        "fetish",
    ],
    "blocked_mime_prefixes": [
        "video/",
        "image/",
    ],
}


class ChildSafetyFirewall:
    def __init__(self, rules: dict | None = None) -> None:
        merged = dict(DEFAULT_RULES)
        if rules:
            for key, value in rules.items():
                merged[key] = value

        self.safe_domains = {d.lower() for d in merged["safe_domains"]}
        self.blocked_domains = {d.lower() for d in merged["blocked_domains"]}
        self.blocked_keywords = {k.lower() for k in merged["blocked_keywords"]}
        self.blocked_mime_prefixes = tuple(merged["blocked_mime_prefixes"])

    @classmethod
    def from_file(cls, path: str | Path) -> "ChildSafetyFirewall":
        with open(path, "r", encoding="utf-8") as fh:
            rules = json.load(fh)
        return cls(rules)

    def inspect_content(self, url: str, title: str = "", mime_type: str = "") -> FirewallDecision:
        domain = self._extract_domain(url)
        joined_text = f"{url} {title}".lower()

        if self._in_domains(domain, self.safe_domains):
            return FirewallDecision(True, f"Allowed: trusted educational domain '{domain}'.")

        if self._in_domains(domain, self.blocked_domains):
            return FirewallDecision(False, f"Blocked: domain '{domain}' is on blocked list.")

        hit = self._keyword_hit(joined_text)
        if hit:
            return FirewallDecision(False, f"Blocked: matched restricted keyword '{hit}'.")

        if mime_type and mime_type.lower().startswith(self.blocked_mime_prefixes):
            # Media itself isn't always unsafe, but for a strict child profile we require trusted source.
            return FirewallDecision(False, "Blocked: direct image/video MIME type from untrusted source.")

        return FirewallDecision(True, "Allowed: no unsafe indicators detected.")

    def inspect_batch(self, records: Iterable[dict]) -> list[FirewallDecision]:
        return [
            self.inspect_content(
                url=record.get("url", ""),
                title=record.get("title", ""),
                mime_type=record.get("mime_type", ""),
            )
            for record in records
        ]

    @staticmethod
    def _extract_domain(url: str) -> str:
        parsed = urlparse(url if re.match(r"^https?://", url) else f"https://{url}")
        return (parsed.netloc or "").lower().split(":")[0]

    @staticmethod
    def _in_domains(target: str, domain_set: set[str]) -> bool:
        if not target:
            return False
        return any(target == domain or target.endswith(f".{domain}") for domain in domain_set)

    def _keyword_hit(self, text: str) -> str | None:
        for keyword in sorted(self.blocked_keywords, key=len, reverse=True):
            if keyword in text:
                return keyword
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple child-safety content firewall")
    parser.add_argument("url", help="URL or domain to inspect")
    parser.add_argument("--title", default="", help="Optional content title")
    parser.add_argument("--mime-type", default="", help="Optional MIME type")
    parser.add_argument("--rules", default="", help="Path to custom JSON rules")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    firewall = ChildSafetyFirewall.from_file(args.rules) if args.rules else ChildSafetyFirewall()
    decision = firewall.inspect_content(args.url, title=args.title, mime_type=args.mime_type)
    print("ALLOW" if decision.allowed else "BLOCK")
    print(decision.reason)


if __name__ == "__main__":
    main()
