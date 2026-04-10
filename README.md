```
  ___  _     _       _
 / __|| |   (_) _ _ | |_
| (_ || |__ | || ' \|  _|
 \___||____||_||_||_|\__|
```

> *The more unique your trail, the easier you are to hunt.*

Local OPSEC auditing tool. Runs in your browser, scores your digital footprint across 4 risk dimensions, and tells you what to fix.

No data leaves your machine except optional external API calls.

---

## Setup

```bash
pip install -e .
cp .env.example .env
python -c "import secrets; print(secrets.token_hex())"
python -m glint
```

Open `http://127.0.0.1:5000`.

---

## What it finds

- WebRTC IP leak — real IP exposed even behind a VPN
- DNS leak — resolver belongs to your ISP, not a private DNS
- Canvas, audio, and WebGL fingerprints — hardware-level uniqueness
- Font enumeration — software signatures (Office, Adobe, CAD)
- HTTP header inconsistencies — language and timezone mismatches
- Email breach exposure (opt-in, HIBP)

---

## Optional API keys

Set in `.env`:

- `HIBP_API_KEY` — haveibeenpwned.com (paid)
- `ABUSEIPDB_API_KEY` — abuseipdb.com (free tier)

---

Part of the [CBS Blue Team](https://github.com/gustavonogvi) ecosystem alongside Naberius and Vassago.
