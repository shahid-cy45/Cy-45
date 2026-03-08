#!/usr/bin/env python3
"""Simple child-safety firewall for filtering adult images/videos and unsafe websites."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

DEFAULT_ADULT_KEYWORDS = {
    "adult",
    "porn",
    "xxx",
    "sex",
    "nude",
    "nudity",
    "escort",
    "camgirl",
    "cams",
    "fetish",
    "hentai",
    "nsfw",
    "18+",
    "onlyfans",
    "playboy",
}

DEFAULT_BLOCKED_DOMAINS = {
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "redtube.com",
    "youporn.com",
}

VIDEO_MIME_PREFIXES = ("video/",)
IMAGE_MIME_PREFIXES = ("image/",)
MEDIA_FILE_EXTENSIONS = {
    ".mp4",
    ".mkv",
    ".webm",
    ".mov",
    ".avi",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tiff",
    ".heic",
}


@dataclass
class FirewallRules:
    adult_keywords: set[str] = field(default_factory=lambda: set(DEFAULT_ADULT_KEYWORDS))
    blocked_domains: set[str] = field(default_factory=lambda: set(DEFAULT_BLOCKED_DOMAINS))
    trusted_domains: set[str] = field(default_factory=lambda: {"kids.youtube.com", "pbskids.org", "natgeokids.com"})

    @classmethod
    def from_json(cls, path: str | Path) -> "FirewallRules":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            adult_keywords=set(data.get("adult_keywords", DEFAULT_ADULT_KEYWORDS)),
            blocked_domains=set(data.get("blocked_domains", DEFAULT_BLOCKED_DOMAINS)),
            trusted_domains=set(data.get("trusted_domains", [])),
        )


@dataclass
class InspectionResult:
    blocked: bool
    reason: str
    safe_url: str | None = None


class ChildSafetyFirewall:
    def __init__(self, rules: FirewallRules | None = None) -> None:
        self.rules = rules or FirewallRules()

    def inspect(self, *, url: str, mime_type: str | None = None, title: str | None = None) -> InspectionResult:
        """Inspect URL + optional metadata and return whether access should be blocked."""
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(":")[0]

        if host in self.rules.trusted_domains:
            return InspectionResult(blocked=False, reason="trusted_domain", safe_url=self.enforce_safe_search(url))

        if self._is_blocked_domain(host):
            return InspectionResult(blocked=True, reason=f"blocked_domain:{host}")

        searchable = " ".join(filter(None, [url, title or "", parsed.path]))
        if self._contains_adult_keyword(searchable):
            return InspectionResult(blocked=True, reason="adult_keyword_detected")

        if mime_type and self._is_media(mime_type):
            if self._contains_adult_keyword(searchable):
                return InspectionResult(blocked=True, reason="adult_media")

        file_suffix = Path(parsed.path).suffix.lower()
        if file_suffix in MEDIA_FILE_EXTENSIONS and self._contains_adult_keyword(searchable):
            return InspectionResult(blocked=True, reason="adult_media_filename")

        return InspectionResult(blocked=False, reason="allowed", safe_url=self.enforce_safe_search(url))

    def enforce_safe_search(self, url: str) -> str:
        """Add safe-search and restrictive flags for common search/video hosts."""
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(":")[0]
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))

        if "google." in host:
            query["safe"] = "active"
        elif host.endswith("bing.com"):
            query["adlt"] = "strict"
        elif host.endswith("youtube.com"):
            query["safe_search"] = "strict"

        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    def _is_blocked_domain(self, host: str) -> bool:
        return any(host == blocked or host.endswith(f".{blocked}") for blocked in self.rules.blocked_domains)

    def _contains_adult_keyword(self, text: str) -> bool:
        lowered = text.lower()
        return any(re.search(rf"\b{re.escape(keyword)}\b", lowered) for keyword in self.rules.adult_keywords)

    @staticmethod
    def _is_media(mime_type: str) -> bool:
        return mime_type.startswith(VIDEO_MIME_PREFIXES + IMAGE_MIME_PREFIXES)


def run_cli(urls: Iterable[str], rules_path: str | None = None) -> int:
    rules = FirewallRules.from_json(rules_path) if rules_path else FirewallRules()
    firewall = ChildSafetyFirewall(rules)

    blocked_count = 0
    for raw in urls:
        url = raw.strip()
        if not url:
            continue
        outcome = firewall.inspect(url=url)
        status = "BLOCK" if outcome.blocked else "ALLOW"
        safe_url = f" | safe_url={outcome.safe_url}" if outcome.safe_url else ""
        print(f"{status} {url} ({outcome.reason}){safe_url}")
        blocked_count += int(outcome.blocked)

    return 1 if blocked_count else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple child-safety firewall URL checker")
    parser.add_argument("urls", nargs="*", help="URLs to inspect")
    parser.add_argument("--input", help="Optional file with one URL per line")
    parser.add_argument("--rules", help="Optional path to custom rules JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    urls = list(args.urls)
    if args.input:
        urls.extend(Path(args.input).read_text(encoding="utf-8").splitlines())

    if not urls:
        print("No URLs provided. Example: python firewall.py https://example.com")
        return 2

    return run_cli(urls, rules_path=args.rules)


if __name__ == "__main__":
    raise SystemExit(main())
