"""Runtime configuration, overridable via ``SOC_``-prefixed environment variables or ``.env``."""

from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
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

# Registered domains each brand legitimately sends from. Consumer mailbox domains
# (gmail.com, outlook.com, icloud.com, ...) are deliberately absent, as are tenant
# namespaces anyone can obtain (onmicrosoft.com, amazonses.com): otherwise
# "Apple Support <x@icloud.com>" would vouch for itself. A brand keyword with no
# entry here is checked against "<brand>.com".
_MICROSOFT: Final = frozenset(
    {
        "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
        "microsoft365.com", "azure.com", "sharepointonline.com",
    }
)
_META: Final = frozenset({"facebook.com", "facebookmail.com", "meta.com", "fb.com"})
_AMAZON: Final = frozenset(
    {
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es",
        "amazon.nl", "amazon.se", "amazon.pl", "amazon.ca", "amazon.com.au", "amazon.co.jp",
        "amazon.in", "amazon.com.br", "amazon.com.mx", "amazon.sg", "amazon.ae",
    }
)
_PAYPAL: Final = frozenset(
    {
        "paypal.com", "paypal.co.uk", "paypal.de", "paypal.fr", "paypal.it", "paypal.es",
        "paypal.nl", "paypal.ca", "paypal.com.au",
    }
)
DEFAULT_BRAND_DOMAINS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "adobe": frozenset({"adobe.com", "adobesign.com"}),
        "amazon": _AMAZON,
        "americanexpress": frozenset({"americanexpress.com", "aexp.com"}),
        "amex": frozenset({"americanexpress.com", "aexp.com"}),
        "apple": frozenset({"apple.com"}),
        "bankofamerica": frozenset({"bankofamerica.com"}),
        "binance": frozenset({"binance.com"}),
        "chase": frozenset({"chase.com", "jpmorgan.com", "jpmchase.com"}),
        "citibank": frozenset({"citi.com", "citibank.com", "citigroup.com"}),
        "coinbase": frozenset({"coinbase.com"}),
        "dhl": frozenset({"dhl.com", "dhl.de", "dhl.co.uk", "dpdhl.com"}),
        "docusign": frozenset({"docusign.com", "docusign.net"}),
        "dropbox": frozenset({"dropbox.com", "dropboxmail.com"}),
        "facebook": _META,
        "fedex": frozenset({"fedex.com"}),
        "gmail": frozenset({"google.com"}),
        "google": frozenset({"google.com"}),
        "hmrc": frozenset({"hmrc.gov.uk"}),
        "hsbc": frozenset({"hsbc.com", "hsbc.co.uk", "hsbc.com.hk"}),
        "icloud": frozenset({"apple.com"}),
        "instagram": _META | {"instagram.com"},
        "irs": frozenset({"irs.gov"}),
        "linkedin": frozenset({"linkedin.com"}),
        "metamask": frozenset({"metamask.io"}),
        "microsoft": _MICROSOFT,
        "netflix": frozenset({"netflix.com"}),
        "office365": _MICROSOFT,
        "okta": frozenset({"okta.com"}),
        "onedrive": _MICROSOFT,
        "outlook": _MICROSOFT,
        "paypal": _PAYPAL,
        "sharepoint": _MICROSOFT,
        "steam": frozenset({"steampowered.com", "steamcommunity.com", "valvesoftware.com"}),
        "ups": frozenset({"ups.com"}),
        "usps": frozenset({"usps.com", "usps.gov"}),
        "wellsfargo": frozenset({"wellsfargo.com", "wf.com"}),
        "whatsapp": _META | {"whatsapp.com"},
        "zoom": frozenset({"zoom.us", "zoom.com"}),
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

    # Scan history. Anchored to the project root, not the working directory.
    DATABASE_URL: str = f"sqlite+aiosqlite:///{(_PROJECT_ROOT / 'soc_intel.db').as_posix()}"

    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_MAX_BYTES: int = Field(default=50 * 1024 * 1024, gt=0)
    LOG_BACKUP_COUNT: int = Field(default=10, ge=0)

    MAX_ATTACHMENT_BYTES: int = Field(default=2 * 1024 * 1024, gt=0)
    MIME_MAX_DEPTH: int = Field(default=32, gt=0)
    MIME_MAX_PARTS: int = Field(default=1000, gt=0)
    MAX_EXTRACTED_URLS: int = Field(default=500, gt=0)
    # Largest raw email the API accepts (uvicorn's own WebSocket frame cap is also 16 MiB).
    MAX_EMAIL_BYTES: int = Field(default=16 * 1024 * 1024, gt=0)
    # Browser origins allowed to call the API. CORS does not cover WebSockets, so the
    # stream endpoint checks the Origin header against this list itself; "*" allows any.
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    # Ample for the prompt's 40-word deduction plus verdict, and a hard stop on a rambling model.
    SLM_MAX_NEW_TOKENS: int = Field(default=160, gt=0)
    # The MemAE decoder is dense (N x N), so graph size must stay bounded whatever the email claims.
    GRAPH_MAX_HOPS: int = Field(default=64, gt=0)
    GRAPH_MAX_URLS: int = Field(default=64, ge=0)

    SANDBOX_TIMEOUT_MS: int = Field(default=4000, gt=0)
    # Phishing kits cloak behind benign pages when they see "HeadlessChrome".
    SANDBOX_USER_AGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    )
    # Chromium's own OS-level sandbox. Disable only where it cannot start (e.g. root in a container).
    SANDBOX_CHROMIUM_OS_SANDBOX: bool = True

    HIGH_RISK_BRAND_KEYWORDS: frozenset[str] = DEFAULT_HIGH_RISK_BRANDS
    BRAND_CANONICAL_DOMAINS: dict[str, frozenset[str]] = Field(
        default_factory=lambda: dict(DEFAULT_BRAND_DOMAINS)
    )
    # authserv-ids of our own boundary MTAs. Empty: trust the topmost Authentication-Results
    # header, which is only safe when the boundary always stamps one.
    TRUSTED_AUTHSERV_IDS: frozenset[str] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def _derive_dirs_from_base(cls, data: Any) -> Any:
        # Moving BASE_DIR should move models/cache/logs with it unless each is pinned explicitly.
        if not isinstance(data, dict) or not data.get("BASE_DIR"):
            return data
        base = Path(data["BASE_DIR"])
        return {**{key: base / name for key, name in _DERIVED_DIRS.items()}, **data}

    @field_validator("HIGH_RISK_BRAND_KEYWORDS", "TRUSTED_AUTHSERV_IDS", mode="after")
    @classmethod
    def _normalise_keywords(cls, value: frozenset[str]) -> frozenset[str]:
        return frozenset(item.strip().casefold() for item in value if item.strip())

    @field_validator("BRAND_CANONICAL_DOMAINS", mode="after")
    @classmethod
    def _normalise_brand_domains(
        cls, value: dict[str, frozenset[str]]
    ) -> dict[str, frozenset[str]]:
        return {
            brand.strip().casefold(): frozenset(d.strip().rstrip(".").casefold() for d in domains)
            for brand, domains in value.items()
        }

    def ensure_dirs(self) -> None:
        for directory in (self.MODELS_DIR, self.CACHE_DIR, self.LOG_DIR):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
