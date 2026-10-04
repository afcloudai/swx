# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

"""
Compliance, GDPR & SOC 2 Settings Mixin.

Defines compliance-related settings: SOC 2 backup status, SIEM integration,
API key scoping, session management, and feature flags.
"""

from pydantic import Field
from pydantic_settings import BaseSettings


class ComplianceSettingsMixin(BaseSettings):
    """Compliance, GDPR and SOC 2 configuration."""

    # Backup Status (SOC 2 CC6.5)
    BACKUP_STATUS_URL: str | None = Field(
        default=None,
        description="External backup system URL for SOC 2 backup verification.",
    )

    # SIEM Integration (SOC 2 CC7.2)
    SIEM_ENABLED: bool = Field(default=False, description="Enable SIEM webhook integration for critical audit events")
    SIEM_WEBHOOK_URL: str | None = Field(default=None, description="Webhook URL for SIEM integration")
    SIEM_BATCH_INTERVAL: int = Field(default=60, description="Seconds between batches of non-critical events sent to SIEM")

    # Session Management (SOC 2 CC6.1)
    MAX_CONCURRENT_SESSIONS: int = Field(default=5, description="Maximum concurrent active sessions per user")
    SESSION_IDLE_TIMEOUT_MINUTES: int = Field(default=60, description="Minutes of inactivity before session expires")
    SESSION_IDLE_CLEANUP_INTERVAL_SECONDS: int = Field(default=3600, description="Seconds between idle session cleanup cycles")
    API_KEY_LIFECYCLE_INTERVAL_SECONDS: int = Field(default=86400, description="Seconds between API key lifecycle cleanup cycles")

    # Feature Flags & A/B Testing
    FEATURE_FLAG_ENABLED: bool = Field(default=True, description="Enable feature flags and A/B testing")

    # Compliance Audit
    COMPLIANCE_ENABLED: bool = Field(default=True, description="Enable compliance audit logging")
    COMPLIANCE_DEFAULT_SEVERITY: str = Field(default="info", description="Default compliance event severity")
    COMPLIANCE_DEFAULT_DATA_CLASSIFICATION: str = Field(default="PUBLIC", description="Default data classification")
    COMPLIANCE_DEFAULT_IP_MASKING: str = Field(default="partial", description="IP masking mode: full | partial | none")
    COMPLIANCE_DEFAULT_RETENTION_DAYS: int = Field(default=365, description="Default compliance retention days")
    COMPLIANCE_AUTO_MASK_IP: bool = Field(default=True, description="Auto-mask IP addresses in audit logs")
    COMPLIANCE_AUTO_REDACT_FIELDS: bool = Field(default=True, description="Auto-redact sensitive fields in audit logs")
    COMPLIANCE_DATA_SUBJECT_REQUEST_EXPIRY_DAYS: int = Field(default=30, description="Days before a data-subject request expires")

    # GDPR
    GDPR_ENABLED: bool = Field(default=True, description="Enable GDPR features")
    GDPR_DELETION_GRACE_DAYS: int = Field(default=30, description="Grace days before anonymization on delete")
    GDPR_EXPORT_FORMAT: str = Field(default="json", description="Default GDPR export format")
    GDPR_ANONYMIZE_ON_DELETE: bool = Field(default=True, description="Anonymize user data on delete")
    GDPR_SOLE_OWNER_BLOCK: bool = Field(default=True, description="Block org deletion while a sole owner remains")

    # API Key Scoping Settings
    API_KEY_ENABLED: bool = True
    API_KEY_DEFAULT_EXPIRY_DAYS: int = 90
    API_KEY_MAX_EXPIRY_DAYS: int = 365
    API_KEY_MAX_INACTIVE_DAYS: int = 180
    API_KEY_ROTATION_GRACE_HOURS: int = 24
    API_KEY_DEFAULT_RATE_LIMIT: int = 60
    API_KEY_CACHE_TTL: int = 300
