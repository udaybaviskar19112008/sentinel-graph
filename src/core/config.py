"""Runtime configuration, overridable via ``SOC_``-prefixed environment variables or ``.env``."""

from functools import lru_cache
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

# Runtime directories that live under BASE_DIR unless overridden individually.
_DERIVED_DIRS: Final[dict[str, str]] = {
    "MODELS_DIR": "models",
    "CACHE_DIR": ".cache",
    "LOG_DIR": "logs",
}

DEFAULT_HIGH_RISK_BRANDS: Final[frozenset[str]] = frozenset(
    {
        "adobe", "amazon", "americanexpress", "amex", "apple", "bankofamerica",
        "binance", "chase", "citibank", "coinbase", "dhl", "docusign", "dropbox",
        "facebook", "fedex", "gmail", "google", "hmrc", "hsbc", "icloud",
        "instagram", "irs", "linkedin", "metamask", "microsoft", "netflix",
        "office365", "okta", "onedrive", "outlook", "paypal", "sharepoint",
        "steam", "ups", "usps", "wellsfargo", "whatsapp", "zoom",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SOC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    BASE_DIR: Path = _PROJECT_ROOT
    MODELS_DIR: Path = _PROJECT_ROOT / _DERIVED_DIRS["MODELS_DIR"]
    CACHE_DIR: Path = _PROJECT_ROOT / _DERIVED_DIRS["CACHE_DIR"]
    LOG_DIR: Path = _PROJECT_ROOT / _DERIVED_DIRS["LOG_DIR"]

    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_MAX_BYTES: int = Field(default=50 * 1024 * 1024, gt=0)
    LOG_BACKUP_COUNT: int = Field(default=10, ge=0)

    MAX_ATTACHMENT_BYTES: int = Field(default=2 * 1024 * 1024, gt=0)
    MIME_MAX_DEPTH: int = Field(default=32, gt=0)
    MIME_MAX_PARTS: int = Field(default=1000, gt=0)

    HIGH_RISK_BRAND_KEYWORDS: frozenset[str] = DEFAULT_HIGH_RISK_BRANDS

    @model_validator(mode="before")
    @classmethod
    def _derive_dirs_from_base(cls, data: Any) -> Any:
        # Moving BASE_DIR should move models/cache/logs with it unless each is pinned explicitly.
        if not isinstance(data, dict) or not data.get("BASE_DIR"):
            return data
        base = Path(data["BASE_DIR"])
        return {**{key: base / name for key, name in _DERIVED_DIRS.items()}, **data}

    @field_validator("HIGH_RISK_BRAND_KEYWORDS", mode="after")
    @classmethod
    def _normalise_brands(cls, value: frozenset[str]) -> frozenset[str]:
        return frozenset(brand.strip().casefold() for brand in value if brand.strip())

    def ensure_dirs(self) -> None:
        for directory in (self.MODELS_DIR, self.CACHE_DIR, self.LOG_DIR):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
