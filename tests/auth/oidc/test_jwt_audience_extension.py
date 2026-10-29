# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false

"""
Unit tests for the SWX-IDM-001 D-5 additive audience extension in auth/core/jwt.py.
"""

from datetime import timedelta

import jwt as pyjwt
import pytest

from swx_core.auth.core.jwt import TokenAudience, create_token, decode_token

pytestmark = pytest.mark.unit


class TestStringAudienceExtension:
    def test_str_audience_create_and_decode_roundtrip(self) -> None:
        token = create_token("user-1", "oidc_client:abc123", timedelta(minutes=5), scopes=["openid"])
        payload = decode_token(token, "oidc_client:abc123")
        assert payload["aud"] == "oidc_client:abc123"
        assert payload["sub"] == "user-1"
        assert payload["scope"] == "openid"

    def test_wrong_str_audience_refused(self) -> None:
        token = create_token("user-1", "oidc_client:abc123", timedelta(minutes=5))
        with pytest.raises(pyjwt.InvalidTokenError, match="(?i)audience"):
            decode_token(token, "oidc_client:other")

    def test_enum_audiences_unchanged(self) -> None:
        token = create_token("ayo@example.com", TokenAudience.USER, timedelta(minutes=5))
        assert decode_token(token, TokenAudience.USER)["aud"] == "user"

    def test_platform_token_cannot_pass_as_oidc_token(self) -> None:
        token = create_token("ayo@example.com", TokenAudience.USER, timedelta(minutes=5))
        with pytest.raises(pyjwt.InvalidTokenError, match="(?i)audience"):
            decode_token(token, "oidc_client:abc123")

    def test_oidc_string_token_cannot_pass_as_platform_token(self) -> None:
        token = create_token("user-1", "oidc_client:abc123", timedelta(minutes=5))
        with pytest.raises(pyjwt.InvalidTokenError, match="(?i)audience"):
            decode_token(token, TokenAudience.USER)