"""
SentinelFlow Configuration Management
Handles all runtime configuration, environment variables, and YAML config loading.
"""

import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any


@dataclass
class Config:
    """Central configuration object for SentinelFlow."""

    # Core settings
    config_file: str = "config/sentinelflow.yaml"
    db_path: str = "sentinelflow.db"
    output_dir: str = "./results"
    verbose: bool = False
    threads: int = 10
    timeout: int = 30
    rate_limit: int = 100
    passive_only: bool = False

    # Telegram
    telegram_token: Optional[str] = None
    telegram_chat: Optional[str] = None

    # Tool paths (auto-detected if in PATH)
    subfinder_path: str = "subfinder"
    httpx_path: str = "httpx"
    naabu_path: str = "naabu"
    nuclei_path: str = "nuclei"
    ffuf_path: str = "ffuf"
    sqlmap_path: str = "sqlmap"

    # API keys for passive recon (loaded from env or config)
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    chaos_api_key: Optional[str] = None

    # Scan settings
    ports: str = "80,443,8080,8443,8000,8888,3000,5000,9000"
    wordlist_path: str = "config/wordlists/common.txt"
    nuclei_templates: str = ""  # Empty = use default templates
    severity_levels: List[str] = field(default_factory=lambda: ["critical", "high", "medium"])
    alert_on_severity: List[str] = field(default_factory=lambda: ["critical", "high"])

    # S3 / Cloud checks
    cloud_providers: List[str] = field(default_factory=lambda: ["aws", "gcp", "azure"])

    # Exclusions
    excluded_subdomains: List[str] = field(default_factory=list)
    excluded_ports: List[int] = field(default_factory=list)

    # Internal state
    _yaml_config: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        """Load config from YAML file and environment variables."""
        self._load_yaml_config()
        self._load_env_vars()
        self._ensure_dirs()

    def _load_yaml_config(self):
        """Load settings from YAML configuration file."""
        config_path = Path(self.config_file)
        if config_path.exists():
            with open(config_path) as f:
                self._yaml_config = yaml.safe_load(f) or {}
            self._apply_yaml_config()

    def _apply_yaml_config(self):
        """Apply YAML config values (env vars take precedence later)."""
        cfg = self._yaml_config

        # Tool paths
        tools = cfg.get("tools", {})
        for tool in ["subfinder", "httpx", "naabu", "nuclei", "ffuf", "sqlmap"]:
            if tool in tools:
                setattr(self, f"{tool}_path", tools[tool])

        # API keys
        api_keys = cfg.get("api_keys", {})
        for key in ["shodan_api_key", "censys_api_id", "censys_api_secret",
                    "virustotal_api_key", "securitytrails_api_key", "chaos_api_key"]:
            if key in api_keys:
                setattr(self, key, api_keys[key])

        # Scan settings
        scan = cfg.get("scan", {})
        if "ports" in scan:
            self.ports = scan["ports"]
        if "wordlist" in scan:
            self.wordlist_path = scan["wordlist"]
        if "severity" in scan:
            self.severity_levels = scan["severity"]
        if "alert_on" in scan:
            self.alert_on_severity = scan["alert_on"]
        if "threads" in scan:
            self.threads = scan["threads"]
        if "timeout" in scan:
            self.timeout = scan["timeout"]
        if "rate_limit" in scan:
            self.rate_limit = scan["rate_limit"]

        # Notifications
        notif = cfg.get("notifications", {})
        telegram = notif.get("telegram", {})
        if "token" in telegram and not self.telegram_token:
            self.telegram_token = telegram["token"]
        if "chat_id" in telegram and not self.telegram_chat:
            self.telegram_chat = telegram["chat_id"]

    def _load_env_vars(self):
        """Load API keys from environment variables (highest priority)."""
        env_map = {
            "SHODAN_API_KEY": "shodan_api_key",
            "CENSYS_API_ID": "censys_api_id",
            "CENSYS_API_SECRET": "censys_api_secret",
            "VIRUSTOTAL_API_KEY": "virustotal_api_key",
            "SECURITYTRAILS_API_KEY": "securitytrails_api_key",
            "CHAOS_API_KEY": "chaos_api_key",
            "TELEGRAM_TOKEN": "telegram_token",
            "TELEGRAM_CHAT_ID": "telegram_chat",
            "SF_DB_PATH": "db_path",
        }
        for env_var, attr in env_map.items():
            value = os.environ.get(env_var)
            if value:
                setattr(self, attr, value)

    def _ensure_dirs(self):
        """Create required directories."""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path("config/wordlists").mkdir(parents=True, exist_ok=True)
        Path("logs").mkdir(parents=True, exist_ok=True)

    @property
    def has_telegram(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat)

    @property
    def results_path(self) -> Path:
        return Path(self.output_dir)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize config to dict (excluding sensitive keys)."""
        return {
            "db_path": self.db_path,
            "output_dir": self.output_dir,
            "threads": self.threads,
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "passive_only": self.passive_only,
            "ports": self.ports,
            "severity_levels": self.severity_levels,
            "alert_on_severity": self.alert_on_severity,
            "has_telegram": self.has_telegram,
        }
