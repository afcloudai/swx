# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

"""
Application Settings Configuration
----------------------------------
This module defines the global settings for the SwX-API.

Features:
- Reads environment variables from `.env` file.
- Configures API, database, security, email, and CORS settings.
- Provides dynamic property-based settings.

The `Settings` class is composed from modular mixins that each define a
coherent group of settings:
- ApiSettingsMixin: API, routing, hosts, environment, logging
- SecuritySettingsMixin: auth tokens, secrets, account lockout
- EncryptionSettingsMixin: at-rest field encryption
- DatabaseSettingsMixin: database connection and pooling
- InfraSettingsMixin: CORS, email, Redis, cookies, rate limiting, CSRF, caches
- FeaturesSettingsMixin: feature toggles and framework configuration
- ComplianceSettingsMixin: compliance, SIEM, API key scoping

Module-level constants below are single-source aliases onto the `settings`
instance: consumers may `from swx_core.config.settings import X` but the
value always comes from the environment-backed Settings fields.
"""

import os
from typing import ClassVar

from pydantic_settings import BaseSettings, SettingsConfigDict

from swx_core.config.settings_api import ApiSettingsMixin
from swx_core.config.settings_compliance import ComplianceSettingsMixin
from swx_core.config.settings_database import DatabaseSettingsMixin
from swx_core.config.settings_encryption import EncryptionSettingsMixin
from swx_core.config.settings_features import FeaturesSettingsMixin
from swx_core.config.settings_infra import InfraSettingsMixin
from swx_core.config.settings_security import SecuritySettingsMixin


class Settings(
    ComplianceSettingsMixin,
    FeaturesSettingsMixin,
    InfraSettingsMixin,
    DatabaseSettingsMixin,
    EncryptionSettingsMixin,
    SecuritySettingsMixin,
    ApiSettingsMixin,
    BaseSettings,
):
    """
    Application-wide settings, loaded from environment variables or `.env` file.

    Composed from modular mixins; see each mixin's docstring for the fields
    it contributes. Kept as a single `BaseSettings` subclass so all settings
    read from `.env` in one pass and expose a unified `settings` instance.
    """

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )

    def model_post_init(self, __context) -> None:
        # MRO note: this class-level definition shadows the mixins' hooks;
        # super() chains them (security mixin fills dev fallback secrets).
        super().model_post_init(__context)

        # extra="ignore" hides .env typos (SECRETT_KEY boots silently). The
        # process env is an open namespace full of unrelated system vars, so
        # the typo check is scoped to .env — the user-owned key surface. The
        # path must match pydantic-settings' env_file=".env" (cwd-relative);
        # bare dotenv_values() frame-walks and resolves a different file.
        from dotenv import dotenv_values

        dotenv_path = type(self).model_config.get("env_file", ".env")
        if not os.path.isfile(dotenv_path):
            return

        known = set(type(self).model_fields.keys())
        unknown = sorted(set(dotenv_values(dotenv_path).keys()) - known)
        if unknown and "PYTEST_CURRENT_TEST" not in os.environ:
            import warnings

            warnings.warn(
                f"Unknown keys in .env will be ignored (typo?): {', '.join(unknown[:10])}"
                + (" ..." if len(unknown) > 10 else ""),
                stacklevel=2,
            )


# Instantiate settings
settings = Settings()  # pyright: ignore[reportCallIssue]

# Module-level aliases onto the settings instance (single source of truth).
# These preserve the historical `from swx_core.config.settings import X`
# surface; values are always the environment-backed Settings fields.

# Compliance Audit
COMPLIANCE_ENABLED = settings.COMPLIANCE_ENABLED
COMPLIANCE_DEFAULT_SEVERITY = settings.COMPLIANCE_DEFAULT_SEVERITY
COMPLIANCE_DEFAULT_DATA_CLASSIFICATION = settings.COMPLIANCE_DEFAULT_DATA_CLASSIFICATION
COMPLIANCE_DEFAULT_IP_MASKING = settings.COMPLIANCE_DEFAULT_IP_MASKING
COMPLIANCE_DEFAULT_RETENTION_DAYS = settings.COMPLIANCE_DEFAULT_RETENTION_DAYS
COMPLIANCE_AUTO_MASK_IP = settings.COMPLIANCE_AUTO_MASK_IP
COMPLIANCE_AUTO_REDACT_FIELDS = settings.COMPLIANCE_AUTO_REDACT_FIELDS
COMPLIANCE_DATA_SUBJECT_REQUEST_EXPIRY_DAYS = settings.COMPLIANCE_DATA_SUBJECT_REQUEST_EXPIRY_DAYS

# GDPR
GDPR_ENABLED = settings.GDPR_ENABLED
GDPR_DELETION_GRACE_DAYS = settings.GDPR_DELETION_GRACE_DAYS
GDPR_EXPORT_FORMAT = settings.GDPR_EXPORT_FORMAT
GDPR_ANONYMIZE_ON_DELETE = settings.GDPR_ANONYMIZE_ON_DELETE
GDPR_SOLE_OWNER_BLOCK = settings.GDPR_SOLE_OWNER_BLOCK
GDPR_EXPORT_EXPIRY_DAYS = settings.GDPR_EXPORT_EXPIRY_DAYS
GDPR_MIN_VERIFICATION_DAYS = settings.GDPR_MIN_VERIFICATION_DAYS

# Notification
NOTIFICATION_ENABLED = settings.NOTIFICATION_ENABLED
NOTIFICATION_DEFAULT_FROM_EMAIL = settings.NOTIFICATION_DEFAULT_FROM_EMAIL
NOTIFICATION_DEFAULT_FROM_NAME = settings.NOTIFICATION_DEFAULT_FROM_NAME
NOTIFICATION_DEFAULT_RETRY_COUNT = settings.NOTIFICATION_DEFAULT_RETRY_COUNT
NOTIFICATION_DEFAULT_TIMEOUT = settings.NOTIFICATION_DEFAULT_TIMEOUT
NOTIFICATION_PROVIDER_CACHE_TTL = settings.NOTIFICATION_PROVIDER_CACHE_TTL
NOTIFICATION_TEMPLATE_CACHE_TTL = settings.NOTIFICATION_TEMPLATE_CACHE_TTL
NOTIFICATION_RATE_LIMIT_DAILY = settings.NOTIFICATION_RATE_LIMIT_DAILY
NOTIFICATION_RATE_LIMIT_HOURLY = settings.NOTIFICATION_RATE_LIMIT_HOURLY
NOTIFICATION_TEMPLATE_DIR = settings.NOTIFICATION_TEMPLATE_DIR
NOTIFICATION_CELERY_TASK_PATH = settings.NOTIFICATION_CELERY_TASK_PATH

# API Key Scoping
API_KEY_ENABLED = settings.API_KEY_ENABLED
API_KEY_DEFAULT_EXPIRY_DAYS = settings.API_KEY_DEFAULT_EXPIRY_DAYS
API_KEY_MAX_EXPIRY_DAYS = settings.API_KEY_MAX_EXPIRY_DAYS
API_KEY_MAX_INACTIVE_DAYS = settings.API_KEY_MAX_INACTIVE_DAYS
API_KEY_ROTATION_GRACE_HOURS = settings.API_KEY_ROTATION_GRACE_HOURS
API_KEY_DEFAULT_RATE_LIMIT = settings.API_KEY_DEFAULT_RATE_LIMIT
API_KEY_CACHE_TTL = settings.API_KEY_CACHE_TTL

# Webhook
WEBHOOK_ENABLED = settings.WEBHOOK_ENABLED
WEBHOOK_DEFAULT_RETRY_COUNT = settings.WEBHOOK_DEFAULT_RETRY_COUNT
WEBHOOK_DEFAULT_RETRY_DELAY = settings.WEBHOOK_DEFAULT_RETRY_DELAY
WEBHOOK_DEFAULT_TIMEOUT = settings.WEBHOOK_DEFAULT_TIMEOUT
WEBHOOK_MAX_RETRIES = settings.WEBHOOK_MAX_RETRIES
WEBHOOK_CIRCUIT_BREAKER_THRESHOLD = settings.WEBHOOK_CIRCUIT_BREAKER_THRESHOLD

# Conversation State
CONVERSATION_ENABLED = settings.CONVERSATION_ENABLED
CONVERSATION_DEFAULT_PAGE_SIZE = settings.CONVERSATION_DEFAULT_PAGE_SIZE
CONVERSATION_MAX_MESSAGE_LENGTH = settings.CONVERSATION_MAX_MESSAGE_LENGTH
CONVERSATION_CACHE_TTL = settings.CONVERSATION_CACHE_TTL

# AI Safety
SAFETY_ENABLED = settings.SAFETY_ENABLED
SAFETY_DEFAULT_ACTION = settings.SAFETY_DEFAULT_ACTION
SAFETY_CACHE_TTL = settings.SAFETY_CACHE_TTL
SAFETY_MAX_CONTENT_LENGTH = settings.SAFETY_MAX_CONTENT_LENGTH
SAFETY_LOG_ALL_CHECKS = settings.SAFETY_LOG_ALL_CHECKS

# Enterprise SSO
SSO_ENABLED = settings.SSO_ENABLED
SSO_CACHE_TTL = settings.SSO_CACHE_TTL
SSO_SESSION_TIMEOUT = settings.SSO_SESSION_TIMEOUT
SSO_ALLOW_MULTIPLE_SESSIONS = settings.SSO_ALLOW_MULTIPLE_SESSIONS

# Status Page
STATUS_ENABLED = settings.STATUS_ENABLED
STATUS_CACHE_TTL = settings.STATUS_CACHE_TTL
STATUS_DEFAULT_PAGE_SIZE = settings.STATUS_DEFAULT_PAGE_SIZE

# Data Transfer
DATA_TRANSFER_ENABLED = settings.DATA_TRANSFER_ENABLED
DATA_TRANSFER_CACHE_TTL = settings.DATA_TRANSFER_CACHE_TTL
DATA_EXPORT_EXPIRY_DAYS = settings.DATA_EXPORT_EXPIRY_DAYS
DATA_EXPORT_MAX_RECORDS = settings.DATA_EXPORT_MAX_RECORDS
DATA_IMPORT_MAX_FILE_SIZE = settings.DATA_IMPORT_MAX_FILE_SIZE

# SOC 2 CC6.5 Backup Status
BACKUP_STATUS_URL = settings.BACKUP_STATUS_URL

# SOC 2 CC7.2 SIEM Integration
SIEM_ENABLED = settings.SIEM_ENABLED
SIEM_WEBHOOK_URL = settings.SIEM_WEBHOOK_URL
SIEM_BATCH_INTERVAL = settings.SIEM_BATCH_INTERVAL

# Feature Flags
FEATURE_FLAG_ENABLED = settings.FEATURE_FLAG_ENABLED
FEATURE_FLAG_CACHE_TTL = settings.FEATURE_FLAG_CACHE_TTL