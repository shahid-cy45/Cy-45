# Child Safety Firewall (Simple)

A small Python firewall that helps block **adult-oriented videos and images** for a child profile.

## What it does

- Blocks requests to known adult domains.
- Blocks content containing adult keywords in URL/title.
- Blocks direct `image/*` and `video/*` MIME responses from untrusted sources.
- Allows trusted educational domains.

> This is a **basic local filter**, not a perfect AI moderation platform.

## Usage

```bash
python3 firewall.py "https://kids.youtube.com/watch?v=abc"
python3 firewall.py "https://example.com/video" --title "adult clips"
python3 firewall.py "https://example.com/file.jpg" --mime-type image/jpeg
```

Use custom rules:

```bash
python3 firewall.py "https://site.com" --rules config/rules.example.json
```

## Run tests

```bash
python3 -m unittest discover -s tests -v
```
