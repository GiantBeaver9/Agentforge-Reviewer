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


def load() -> Config:
    def g(key: str, default: str = "") -> str:
        return os.environ.get(key, default)

    return Config(
        target=TargetConfig(
            base_url=g("AGENTFORGE_TARGET_BASE_URL",
                       "https://abundant-art-production-d560.up.railway.app"),
            auth_mode=g("AGENTFORGE_TARGET_AUTH_MODE", "session"),
            username=g("AGENTFORGE_TARGET_USERNAME"),
            password=g("AGENTFORGE_TARGET_PASSWORD"),
            api_key=g("AGENTFORGE_TARGET_API_KEY"),
        ),
        redteam=ModelConfig(
            base_url=g("REDTEAM_BASE_URL", "http://localhost:11434/v1"),
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
