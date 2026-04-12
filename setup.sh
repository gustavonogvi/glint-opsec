#!/usr/bin/env bash
set -e

echo ""
echo "  ___  _     _       _"
echo " / __|| |   (_) _ _ | |_"
echo "| (_ || |__ | || ' \\|  _|"
echo " \\___||____||_||_||_|\\__|"
echo ""
echo "glint — setup"
echo "-------------"
echo ""

# ── uv ────────────────────────────────────────────────────────────────────────
if ! command -v uv &>/dev/null; then
    echo "[+] installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "[ok] uv found: $(uv --version)"
fi

# ── dependencies ──────────────────────────────────────────────────────────────
echo "[+] installing dependencies..."
uv sync

# ── .env ──────────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    SECRET=$(uv run python -c "import secrets; print(secrets.token_hex())")
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/change-me-generate-a-real-secret/$SECRET/" .env
    else
        sed -i "s/change-me-generate-a-real-secret/$SECRET/" .env
    fi
    echo "[+] .env created with generated SECRET_KEY"
else
    echo "[ok] .env already exists — skipping"
fi

# ── cloudflared (optional) ────────────────────────────────────────────────────
echo ""
read -r -p "[?] install cloudflared for public URL testing? (y/N) " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    if command -v cloudflared &>/dev/null; then
        echo "[ok] cloudflared already installed"
    elif command -v brew &>/dev/null; then
        brew install cloudflare/cloudflare/cloudflared
    elif command -v apt-get &>/dev/null; then
        curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
            | sudo tee /usr/share/keyrings/cloudflare-main.gpg > /dev/null
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
            | sudo tee /etc/apt/sources.list.d/cloudflared.list
        sudo apt-get update && sudo apt-get install -y cloudflared
    else
        echo "[!] could not detect package manager — install cloudflared manually:"
        echo "    https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    fi
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo "done."
echo ""
echo "  run server:       uv run python -m glint"
echo "  public tunnel:    cloudflared tunnel --url http://localhost:5000"
echo ""
