import json
import os
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).parent / "data" / "config.json"
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", str(DEFAULT_CONFIG_PATH)))

DEFAULT_CONFIG = {
    "f5_tenant_url": "",
    "f5_api_token": "",
    "llm_base_url": "",
    "llm_api_key": "",
    "llm_model": "",
}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
            cfg = DEFAULT_CONFIG.copy()
            cfg.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
            return cfg
        except (json.JSONDecodeError, OSError):
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    merged = DEFAULT_CONFIG.copy()
    merged.update({k: v for k, v in cfg.items() if k in DEFAULT_CONFIG})
    CONFIG_PATH.write_text(json.dumps(merged, indent=2))


def reset_config() -> None:
    """Wipes saved Settings back to empty defaults — used when moving to a
    different tenant so nothing from the previous one lingers."""
    if CONFIG_PATH.exists():
        CONFIG_PATH.unlink()


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}{'•' * 8}{value[-4:]}"
