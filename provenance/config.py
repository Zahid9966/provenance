import json, os, secrets
from pathlib import Path

HOME = Path(os.environ.get("PROVENANCE_HOME", Path(__file__).resolve().parent.parent / "data"))
LANDING = HOME / "landing"
DB_PATH = HOME / "provenance.db"
KEYS_PATH = HOME / "keys.json"

CHANNELS = {  # expected commercial terms per channel (paise / fractions)
    "STORE": {"kind": "gateway", "commission": 0.0, "fixed_fee": 0, "withholding": 0.0},
    "B2B":   {"kind": "gateway", "commission": 0.0, "fixed_fee": 0, "withholding": 0.0},
    "QCOM":  {"kind": "marketplace", "commission": 0.18, "fixed_fee": 0, "withholding": 0.01},
    "MKTPL": {"kind": "marketplace", "commission": 0.12, "fixed_fee": 2000, "withholding": 0.01},
}
ANCHOR_DIR = Path(os.environ.get("PROVENANCE_ANCHOR_DIR", HOME / "anchors"))   # in production: a separate, append-only/WORM mount
MAPPINGS_PATH = HOME / "mappings.json"      # partner column-mapping profiles (no code change to onboard a partner)
CHANNELS_PATH = HOME / "channels.json"      # per-channel commercial terms


def load_channels():
    """Merge channel terms from data/channels.json over the built-in defaults."""
    if CHANNELS_PATH.exists():
        for name, cfg in json.loads(CHANNELS_PATH.read_text()).items():
            base = {"kind": "marketplace", "commission": 0.0, "fixed_fee": 0, "withholding": 0.0}
            CHANNELS[name] = {**base, **cfg}
    return CHANNELS


def load_mappings() -> dict:
    return json.loads(MAPPINGS_PATH.read_text()) if MAPPINGS_PATH.exists() else {}


TOLERANCE = 100          # paise: variances at or below this are rounding noise
SETTLEMENT_SLA_DAYS = 10  # delivered marketplace order unsettled beyond this => missing


def keys() -> dict:
    """Per-install secrets (PII tokenization, audit HMAC, session signing). Created once, mode 0600."""
    HOME.mkdir(parents=True, exist_ok=True)
    if not KEYS_PATH.exists():
        k = {n: secrets.token_hex(32) for n in ("pii", "audit", "session")}
        fd = os.open(KEYS_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(k, f)
    return json.loads(KEYS_PATH.read_text())
