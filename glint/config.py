import os
import secrets
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    SECRET_KEY: str = field(default_factory=lambda: os.getenv("SECRET_KEY", secrets.token_hex()))
    DATABASE_PATH: str = field(default_factory=lambda: os.getenv("DATABASE_PATH", "glint.db"))
    HIBP_API_KEY: str = field(default_factory=lambda: os.getenv("HIBP_API_KEY", ""))
    ABUSEIPDB_API_KEY: str = field(default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY", ""))
    RISK_WEIGHTS: dict[str, float] = field(default_factory=lambda: {
        "anonymity": 0.30,
        "network": 0.35,
        "data_exposure": 0.25,
        "ip_reputation": 0.10,
    })
    CLEAN_RESOLVERS: list[str] = field(default_factory=lambda: [
        "1.1.1.1",   # Cloudflare
        "8.8.8.8",   # Google
        "9.9.9.9",   # Quad9
    ])
