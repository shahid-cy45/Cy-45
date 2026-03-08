# Child Safety Firewall (Simple)

A lightweight Python firewall-like filter that helps block adult websites, videos, and pictures for children.

## Features
- Blocks known adult domains.
- Detects adult keywords in URLs/titles/file names.
- Adds safe-search flags for Google, Bing, and YouTube links.
- Supports custom rules via JSON.

## Usage
```bash
python firewall.py https://google.com/search?q=kids+games
python firewall.py --input urls.txt
python firewall.py --rules rules.sample.json https://example.com
```

## Example output
```text
ALLOW https://google.com/search?q=kids+games (allowed) | safe_url=https://google.com/search?q=kids+games&safe=active
BLOCK https://xvideos.com (blocked_domain:xvideos.com)
```

## Notes
This is a simple starter firewall and does **not** replace enterprise parental control software. It is best used as a first layer that can be expanded with:
- DNS-level blocking
- Real-time image/video classification
- Browser/device policy management
