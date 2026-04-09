# Glint

Local OPSEC auditing tool. Measures how unique and traceable your browser fingerprint is.

Runs entirely on your machine — no data sent anywhere except optional external API calls (HIBP, ip-api.com).

---

## How it works

Open it in your browser. It collects what any website could collect about you:

- Canvas and audio fingerprints
- Installed fonts (grouped by software: Office, Adobe, etc.)
- Navigator properties, screen geometry
- WebRTC IP leak (your real IP even behind a VPN)
- DNS leak detection
- HTTP header inconsistencies

Scores everything across 4 dimensions and gives you a hardening guide based on what it found.

---

## Setup

```bash
pip install -e .
cp .env.example .env
python -c "import secrets; print(secrets.token_hex())"  # paste into SECRET_KEY
python -m glint
```

Open `http://127.0.0.1:5000`.

---

## Optional API keys

Set in `.env`:

- `HIBP_API_KEY` — email breach check (paid, haveibeenpwned.com)
- `ABUSEIPDB_API_KEY` — IP abuse score (free tier, abuseipdb.com)

Both are optional. The tool works without them.

---

Part of the [CBS Blue Team](https://github.com/gustavonogvi) ecosystem alongside Naberius and Vassago.
