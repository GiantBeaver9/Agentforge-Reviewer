"""Environment-backed configuration. Parse at the boundary into a typed object;
the rest of the platform never reads os.environ directly."""
from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # dotenv optional
    pass


@dataclass(frozen=True)
class TargetConfig:
    base_url: str
    auth_mode: str          # session | apikey | none
    username: str
    password: str
    api_key: str

    @property
    def public_base(self) -> str:
        return (self.base_url.rstrip("/") +
                "/interface/modules/custom_modules/oe-module-clinical-copilot/public")


@dataclass(frozen=True)
class ModelConfig:
    base_url: str
    model: str
    api_key: str


@dataclass(frozen=True)
class BudgetConfig:
    max_usd_per_run: float
    max_attempts_per_campaign: int
    max_turns: int


@dataclass(frozen=True)
class Config:
    target: TargetConfig
    redteam: ModelConfig
    judge: ModelConfig
    budget: BudgetConfig


def _normalize_base_url(url: str) -> str:
    """Tidy a target base URL: trim, add a scheme if the user omitted one, drop a
    trailing slash. ``my-host.up.railway.app`` -> ``https://my-host.up.railway.app``.
    An empty value stays empty (callers surface a clear 'not set' message)."""
    url = (url or "").strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def load() -> Config:
    def g(key: str, default: str = "") -> str:
        # os.environ.get returns "" for a var that is SET but empty, which would
        # shadow the default; treat blank as unset so the default applies.
        val = os.environ.get(key)
        return val if (val is not None and val.strip() != "") else default

    return Config(
        target=TargetConfig(
            base_url=_normalize_base_url(g("AGENTFORGE_TARGET_BASE_URL",
                       "https://abundant-art-production-d560.up.railway.app")),
            auth_mode=g("AGENTFORGE_TARGET_AUTH_MODE", "session"),
            username=g("AGENTFORGE_TARGET_USERNAME"),
            password=g("AGENTFORGE_TARGET_PASSWORD"),
            api_key=g("AGENTFORGE_TARGET_API_KEY"),
        ),
        redteam=ModelConfig(
            # Opt-in: empty base_url => deterministic mutation operators (no LLM).
            # Set REDTEAM_BASE_URL to an OpenAI-compatible endpoint to enable it.
            base_url=g("REDTEAM_BASE_URL", ""),
            model=g("REDTEAM_MODEL", "llama3.1:8b"),
            api_key=g("REDTEAM_API_KEY", "ollama"),
        ),
        judge=ModelConfig(
            base_url=g("JUDGE_BASE_URL", ""),
            model=g("JUDGE_MODEL", "gemini-1.5-pro"),
            api_key=g("JUDGE_API_KEY"),
        ),
        budget=BudgetConfig(
            max_usd_per_run=float(g("AGENTFORGE_MAX_USD_PER_RUN", "2.00")),
            max_attempts_per_campaign=int(g("AGENTFORGE_MAX_ATTEMPTS_PER_CAMPAIGN", "50")),
            max_turns=int(g("AGENTFORGE_MAX_TURNS", "6")),
        ),
    )
