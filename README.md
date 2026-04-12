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

**Linux / Mac:**
```bash
chmod +x setup.sh && ./setup.sh
```

**Windows (PowerShell):**
```powershell
.\setup.ps1
```

Both scripts install [uv](https://github.com/astral-sh/uv) if needed, install dependencies, generate `.env` with a random `SECRET_KEY`, and optionally install `cloudflared` for public URL testing.

Manual setup if you prefer:
```bash
pip install -e .
cp .env.example .env
python -c "import secrets; print(secrets.token_hex())"  # add to .env as SECRET_KEY
python -m glint
```

---

## Testing

### Local (limited)

Open `http://127.0.0.1:5000`.

Works for fingerprint collection (canvas, audio, fonts, WebGL, navigator, screen).  
Network findings that depend on your real IP won't fire — the server sees `127.0.0.1`, so WEBRTC_VPN_BYPASS and IP reputation checks are skipped automatically.

### Public (full assessment)

To test all findings including WebRTC VPN bypass and IP reputation, expose the server via a tunnel:

**ngrok:**
```bash
ngrok http 5000
```

**Cloudflare Tunnel** (no account needed):
```bash
# install once
winget install Cloudflare.cloudflared

# run
cloudflared tunnel --url http://localhost:5000
```

Both give you a temporary public URL. Open it from a different network (mobile on 4G, another machine) to get a real assessment. The server already reads `X-Forwarded-For` headers set by these proxies — no extra configuration needed.

For a meaningful VPN bypass test: enable your VPN, open the URL, and check if WEBRTC_VPN_BYPASS fires.

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
