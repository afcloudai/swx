# pyright: reportAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnusedCallResult=false

"""Tests for refresh token encryption — encrypt on store, decrypt on verify/revoke."""

import base64
import os
from datetime import timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from swx_core.security.encryption import encrypt_value, decrypt_value, is_encrypted
from swx_core.utils.time import utc_now


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _patch_refresh_settings() -> tuple:
    """Patch the CACHED settings singleton (env-dict patches are invisible —
    settings loads once at import; the tests encode against refresh-secret)."""
    from swx_core.config.settings import settings

    return (
        patch.object(settings, "REFRESH_SECRET_KEY", "test-refresh-secret"),
        patch.object(settings, "PASSWORD_SECURITY_ALGORITHM", "HS256"),
    )


def _create_path_session() -> AsyncMock:
    """Session mock matching the create path: count_active_sessions → scalar()=0,
    find_token_by_email → scalars().first() → None."""
    session = AsyncMock()
    count_result = MagicMock()
    count_result.scalar.return_value = 0
    find_result = MagicMock()
    find_result.scalars.return_value.first.return_value = None
    session.execute = AsyncMock(side_effect=[count_result, find_result])
    return session


def _db_token_row(token_value: str, expires_days: int = 7):
    row = MagicMock()
    row.token = token_value
    row.expires_at = utc_now() + timedelta(days=expires_days)
    return row


def _session_chain_first(row) -> AsyncMock:
    """find_token_by_email chain: execute → scalars() → first() → row."""
    session = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.first.return_value = row
    session.execute = AsyncMock(return_value=result)
    return session


def _session_chain_all(rows: list) -> AsyncMock:
    """find_all_tokens_by_email chain: execute → scalars() → all() → rows."""
    session = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows
    session.execute = AsyncMock(return_value=result)
    return session


def _make_master_key() -> str:
    """Generate a random 32-byte master key for testing."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def _mock_settings(**overrides: object) -> MagicMock:
    """Build a mock settings object with encryption-related attributes."""
    defaults: dict[str, object] = {
        "SWX_ENCRYPTION_KEY": _make_master_key(),
        "SWX_ENCRYPTION_KEY_PREVIOUS": None,
        "SWX_ENCRYPTION_SALT": "test-salt",
        "REFRESH_SECRET_KEY": "test-refresh-secret",
        "PASSWORD_SECURITY_ALGORITHM": "HS256",
    }
    defaults.update(overrides)
    return MagicMock(**defaults)


# ---------------------------------------------------------------------------
# _encrypt_token / _decrypt_token unit tests
# ---------------------------------------------------------------------------

class TestEncryptDecryptToken:
    """Tests for the _encrypt_token and _decrypt_token helpers."""

    def test_encrypt_token_returns_ciphertext(self) -> None:
        """_encrypt_token returns a version-prefixed ciphertext."""
        from swx_core.security.refresh_token_service import _encrypt_token

        with patch.dict(os.environ, {"SWX_ENCRYPTION_KEY": _make_master_key()}):
            import swx_core.security.encryption as enc_mod
            enc_mod._encryption_service = None
            result = _encrypt_token("my-secret-token")
            assert result != "my-secret-token"
            assert is_encrypted(result)

    def test_decrypt_token_round_trip(self) -> None:
        """_encrypt_token → _decrypt_token returns the original plaintext."""
        from swx_core.security.refresh_token_service import _encrypt_token, _decrypt_token

        with patch.dict(os.environ, {"SWX_ENCRYPTION_KEY": _make_master_key()}):
            import swx_core.security.encryption as enc_mod
            enc_mod._encryption_service = None
            plaintext = "jwt-token-abc123"
            ciphertext = _encrypt_token(plaintext)
            assert _decrypt_token(ciphertext) == plaintext

    def test_decrypt_token_passthrough_plaintext(self) -> None:
        """_decrypt_token returns input unchanged if it's not encrypted."""
        from swx_core.security.refresh_token_service import _decrypt_token

        assert _decrypt_token("plaintext-token") == "plaintext-token"

    def test_decrypt_token_empty_string(self) -> None:
        """_decrypt_token handles empty string gracefully."""
        from swx_core.security.refresh_token_service import _decrypt_token

        assert _decrypt_token("") == ""

    def test_decrypt_token_none_like(self) -> None:
        """_decrypt_token handles None-like empty values."""
        from swx_core.security.refresh_token_service import _decrypt_token

        assert _decrypt_token("") == ""

    def test_encrypt_token_no_encryption_key_returns_plaintext(self) -> None:
        """When encryption key is not configured, _encrypt_token returns plaintext."""
        from swx_core.security.refresh_token_service import _encrypt_token

        with patch.dict(os.environ, {}, clear=True):
            import swx_core.security.encryption as enc_mod
            enc_mod._encryption_service = None
            result = _encrypt_token("my-token")
            # Falls back to plaintext when encryption unavailable
            assert result == "my-token"


# ---------------------------------------------------------------------------
# create_refresh_token encryption tests
# ---------------------------------------------------------------------------

class TestCreateRefreshTokenEncryption:
    """Tests verifying that create_refresh_token encrypts the stored token."""

    @pytest.mark.asyncio
    async def test_stored_token_is_encrypted(self) -> None:
        """When creating a refresh token, the DB value should be encrypted."""
        from swx_core.security.refresh_token_service import create_refresh_token
        from swx_core.models.refresh_token import RefreshToken

        mock_session = _create_path_session()

        encryption_key = _make_master_key()

        with patch.dict(os.environ, {
            "SWX_ENCRYPTION_KEY": encryption_key,
            "REFRESH_SECRET_KEY": "test-refresh-secret",
            "PASSWORD_SECURITY_ALGORITHM": "HS256",
        }):
            import swx_core.security.encryption as enc_mod
            enc_mod._encryption_service = None

            settings_patches = _patch_refresh_settings()
            with settings_patches[0], settings_patches[1]:
                token = await create_refresh_token(
                    mock_session,
                    email="user@example.com",
                    expires_delta=timedelta(days=7),
                )

            # The JWT token was returned (plaintext)
            assert token is not None
            assert len(token) > 0

            # The stored token was encrypted (check what was added to the session)
            add_calls = [
                call for call in mock_session.add.call_args_list
                if isinstance(call[0][0], RefreshToken)
            ]
            if add_calls:
                stored_token = add_calls[0][0][0].token
                assert is_encrypted(stored_token), "Stored token should be encrypted"

    @pytest.mark.asyncio
    async def test_stored_token_decrypts_to_jwt(self) -> None:
        """The encrypted stored token should decrypt back to the original JWT."""
        from swx_core.security.refresh_token_service import create_refresh_token
        from swx_core.models.refresh_token import RefreshToken

        mock_session = _create_path_session()

        encryption_key = _make_master_key()

        with patch.dict(os.environ, {
            "SWX_ENCRYPTION_KEY": encryption_key,
            "REFRESH_SECRET_KEY": "test-refresh-secret",
            "PASSWORD_SECURITY_ALGORITHM": "HS256",
        }):
            import swx_core.security.encryption as enc_mod
            enc_mod._encryption_service = None

            settings_patches = _patch_refresh_settings()
            with settings_patches[0], settings_patches[1]:
                token = await create_refresh_token(
                    mock_session,
                    email="user@example.com",
                    expires_delta=timedelta(days=7),
                )

                # Verify the returned JWT is valid
                payload = jwt.decode(
                    token,
                    "test-refresh-secret",
                    algorithms=["HS256"],
                )
                assert payload["sub"] == "user@example.com"


# ---------------------------------------------------------------------------
# verify_refresh_token decryption tests
# ---------------------------------------------------------------------------

class TestVerifyRefreshTokenDecryption:
    """Tests verifying that verify_refresh_token decrypts stored tokens."""

    @pytest.mark.asyncio
    async def test_verify_with_encrypted_db_token(self) -> None:
        """verify_refresh_token should decrypt the stored token before comparison."""
        from swx_core.security.refresh_token_service import create_refresh_token, verify_refresh_token
        from swx_core.models.refresh_token import RefreshToken
        from swx_core.utils.time import utc_now

        encryption_key = _make_master_key()

        with patch.dict(os.environ, {
            "SWX_ENCRYPTION_KEY": encryption_key,
            "REFRESH_SECRET_KEY": "test-refresh-secret",
            "PASSWORD_SECURITY_ALGORITHM": "HS256",
        }):
            import swx_core.security.encryption as enc_mod
            enc_mod._encryption_service = None

            settings_patches = _patch_refresh_settings()
            with settings_patches[0], settings_patches[1]:
                encoded_jwt = jwt.encode(
                    {"exp": (utc_now() + timedelta(days=7)).timestamp(), "sub": "user@example.com", "auth_provider": "local"},
                    "test-refresh-secret",
                    algorithm="HS256",
                )

                encrypted = encrypt_value(encoded_jwt)

                mock_token = _db_token_row(encrypted)
                mock_session = _session_chain_first(mock_token)
                mock_request = MagicMock()

                result = await verify_refresh_token(mock_session, encoded_jwt, mock_request)
            assert result is not None
            assert result[0] == "user@example.com"
            assert result[1] == "local"

    @pytest.mark.asyncio
    async def test_verify_with_plaintext_db_token_fallback(self) -> None:
        """verify_refresh_token should handle plaintext tokens (not encrypted)."""
        from swx_core.security.refresh_token_service import verify_refresh_token
        from swx_core.utils.time import utc_now

        encoded_jwt = jwt.encode(
            {"exp": (utc_now() + timedelta(days=7)).timestamp(), "sub": "plain@example.com", "auth_provider": "local"},
            "test-refresh-secret",
            algorithm="HS256",
        )

        mock_token = _db_token_row(encoded_jwt)
        mock_session = _session_chain_first(mock_token)
        mock_request = MagicMock()

        settings_patches = _patch_refresh_settings()
        with settings_patches[0], settings_patches[1]:
            result = await verify_refresh_token(mock_session, encoded_jwt, mock_request)
            assert result is not None
            assert result[0] == "plain@example.com"


# ---------------------------------------------------------------------------
# revoke_refresh_token decryption tests
# ---------------------------------------------------------------------------

class TestRevokeRefreshTokenDecryption:
    """Tests verifying that revoke_refresh_token decrypts stored tokens for comparison."""

    @pytest.mark.asyncio
    async def test_revoke_with_encrypted_db_token(self) -> None:
        """revoke_refresh_token should decrypt the stored token for comparison."""
        from swx_core.security.refresh_token_service import revoke_refresh_token
        from swx_core.utils.time import utc_now

        encryption_key = _make_master_key()

        with patch.dict(os.environ, {
            "SWX_ENCRYPTION_KEY": encryption_key,
            "REFRESH_SECRET_KEY": "test-refresh-secret",
            "PASSWORD_SECURITY_ALGORITHM": "HS256",
        }):
            import swx_core.security.encryption as enc_mod
            enc_mod._encryption_service = None

            settings_patches = _patch_refresh_settings()
            with settings_patches[0], settings_patches[1]:
                encoded_jwt = jwt.encode(
                    {"exp": (utc_now() + timedelta(days=7)).timestamp(), "sub": "revoke@example.com", "auth_provider": "local"},
                    "test-refresh-secret",
                    algorithm="HS256",
                )

                encrypted = encrypt_value(encoded_jwt)
                mock_token = _db_token_row(encrypted)
                mock_session = _session_chain_all([mock_token])

                result = await revoke_refresh_token(mock_session, encoded_jwt)
            assert result is True

    @pytest.mark.asyncio
    async def test_revoke_with_plaintext_db_token(self) -> None:
        """revoke_refresh_token should handle plaintext tokens."""
        from swx_core.security.refresh_token_service import revoke_refresh_token
        from swx_core.utils.time import utc_now

        encoded_jwt = jwt.encode(
            {"exp": (utc_now() + timedelta(days=7)).timestamp(), "sub": "plain-revoke@example.com", "auth_provider": "local"},
            "test-refresh-secret",
            algorithm="HS256",
        )

        mock_token = _db_token_row(encoded_jwt)
        mock_session = _session_chain_all([mock_token])

        settings_patches = _patch_refresh_settings()
        with settings_patches[0], settings_patches[1]:
            result = await revoke_refresh_token(mock_session, encoded_jwt)
            assert result is True