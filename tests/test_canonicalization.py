"""Tests for RFC 8785 JSON Canonicalization Scheme (JCS) and plan hashing."""

from __future__ import annotations

import math
from datetime import datetime, timezone
import pytest

from src.core.exceptions import CanonicalizationError
from src.models.enums import PermissionScope, StepActionType
from src.models.plans import CanonicalApprovalPayload, PlannedStep, SetupPlan
from src.security.canonicalization import (
    canonicalize,
    compute_plan_hash,
    extract_canonical_payload_from_plan,
)


def test_official_rfc8785_key_sorting() -> None:
    """Verify object keys are sorted strictly by UTF-16 code units per RFC 8785 Section 3.2.3."""
    # Test vector with mixed ASCII, symbols, and high Unicode
    data = {
        "\u20ac": "Euro",
        "b": "second",
        "a": "first",
        "1": "numeric-key",
        "\u00a9": "Copyright",
    }
    result = canonicalize(data)
    # RFC 8785 sorting by UTF-16 code units:
    # '1' (0x0031) < 'a' (0x0061) < 'b' (0x0062) < '\u00a9' (0x00A9) < '\u20ac' (0x20AC)
    expected_text = '{"1":"numeric-key","a":"first","b":"second","\u00a9":"Copyright","\u20ac":"Euro"}'
    assert result.canonical_text == expected_text
    assert result.canonical_bytes == expected_text.encode("utf-8")


def test_official_rfc8785_number_formatting() -> None:
    """Verify numbers conform to ECMAScript standard number formatting per RFC 8785 Section 3.2.2.3."""
    test_cases = [
        ({"num": 0.0}, '{"num":0}'),
        ({"num": -0.0}, '{"num":0}'),
        ({"num": 1.0}, '{"num":1}'),
        ({"num": 42}, '{"num":42}'),
        ({"num": 100000000000000000000.0}, '{"num":100000000000000000000}'),
        ({"num": 1e21}, '{"num":1e+21}'),
        ({"num": 1e-6}, '{"num":0.000001}'),
        ({"num": 1e-7}, '{"num":1e-7}'),
    ]
    for input_data, expected in test_cases:
        res = canonicalize(input_data)
        assert res.canonical_text == expected


def test_official_rfc8785_string_escaping() -> None:
    """Verify only quotation mark, backslash, and C0 control characters are escaped."""
    data = {
        "text": 'Quoted "hello" and backslash \\ and newline \n and tab \t and unicode \u2764'
    }
    result = canonicalize(data)
    expected = '{"text":"Quoted \\"hello\\" and backslash \\\\ and newline \\n and tab \\t and unicode \u2764"}'
    assert result.canonical_text == expected


def test_unicode_preservation_no_normalization() -> None:
    """
    CRITICAL RFC 8785 RULE:
    Unicode strings must NOT be normalized (no NFC or NFD transformation).
    'e\\u0301' (NFD, 2 code points) and '\\u00e9' (NFC, 1 code point) MUST NOT produce identical bytes.
    """
    nfd_string = "e\u0301"  # 'e' + COMBINING ACUTE ACCENT (2 code points)
    nfc_string = "\u00e9"   # LATIN SMALL LETTER E WITH ACUTE (1 code point)

    res_nfd = canonicalize({"word": nfd_string})
    res_nfc = canonicalize({"word": nfc_string})

    # Bytes must be different
    assert res_nfd.canonical_bytes != res_nfc.canonical_bytes
    assert res_nfd.sha256_digest != res_nfc.sha256_digest

    # Verify NFD byte sequence contains 0x65, 0xcc, 0x81
    assert res_nfd.canonical_bytes == b'{"word":"e\xcc\x81"}'
    # Verify NFC byte sequence contains 0xc3, 0xa9
    assert res_nfc.canonical_bytes == b'{"word":"\xc3\xa9"}'


def test_rejection_of_nan_and_infinity() -> None:
    """Verify RFC 8785 rejects NaN, Infinity, and -Infinity values."""
    with pytest.raises(CanonicalizationError):
        canonicalize({"bad_float": float("nan")})

    with pytest.raises(CanonicalizationError):
        canonicalize({"bad_float": float("inf")})

    with pytest.raises(CanonicalizationError):
        canonicalize({"bad_float": float("-inf")})


def test_rejection_of_unsupported_types() -> None:
    """Verify unsupported types such as sets or non-string dictionary keys are rejected."""
    # Sets are not valid JSON
    with pytest.raises(CanonicalizationError):
        canonicalize({"tags": {"tag1", "tag2"}})

    # Non-string dictionary keys
    with pytest.raises(CanonicalizationError):
        canonicalize({123: "numeric key"})  # type: ignore[dict-item]


def test_plan_hash_stability() -> None:
    """Verify identical plans produce the exact same canonical hash."""
    payload1 = CanonicalApprovalPayload(
        request_id="req-100",
        target_environment="local-sandbox",
        plan_version=1,
        granted_scopes=["sandbox:create", "data:seed:synthetic"],
        planned_actions=[
            {
                "step_id": "step-00000001",
                "action_type": StepActionType.PROVISION_MOCK_SANDBOX.value,
                "is_privileged": True,
                "required_scopes": ["sandbox:create"],
                "action_parameters": {"memory_mb": 2048},
            }
        ],
        synthetic_fixtures=["users.json", "teams.json"],
    )

    payload2 = CanonicalApprovalPayload(
        request_id="req-100",
        target_environment="local-sandbox",
        plan_version=1,
        granted_scopes=["data:seed:synthetic", "sandbox:create"],  # Different order initially
        planned_actions=[
            {
                "step_id": "step-00000001",
                "action_type": StepActionType.PROVISION_MOCK_SANDBOX.value,
                "is_privileged": True,
                "required_scopes": ["sandbox:create"],
                "action_parameters": {"memory_mb": 2048},
            }
        ],
        synthetic_fixtures=["teams.json", "users.json"],  # Different order initially
    )

    hash1 = compute_plan_hash(payload1)
    hash2 = compute_plan_hash(payload2)
    assert hash1 == hash2
    assert len(hash1) == 64


def test_plan_hash_divergence_on_any_change() -> None:
    """Verify any meaningful change in the plan produces a different canonical SHA-256 fingerprint."""
    base = CanonicalApprovalPayload(
        request_id="req-100",
        target_environment="local-sandbox",
        plan_version=1,
        granted_scopes=["sandbox:create"],
        planned_actions=[
            {
                "step_id": "step-00000001",
                "action_type": StepActionType.PROVISION_MOCK_SANDBOX.value,
                "is_privileged": True,
                "required_scopes": ["sandbox:create"],
                "action_parameters": {"memory_mb": 2048},
            }
        ],
        synthetic_fixtures=["users.json"],
    )
    base_hash = compute_plan_hash(base)

    # 1. Changed request_id
    h1 = compute_plan_hash(
        CanonicalApprovalPayload(**{**base.model_dump(), "request_id": "req-101"})
    )
    assert h1 != base_hash

    # 2. Changed target_environment
    h2 = compute_plan_hash(
        CanonicalApprovalPayload(**{**base.model_dump(), "target_environment": "staging-sandbox"})
    )
    assert h2 != base_hash

    # 3. Changed plan_version
    h3 = compute_plan_hash(
        CanonicalApprovalPayload(**{**base.model_dump(), "plan_version": 2})
    )
    assert h3 != base_hash

    # 4. Changed granted_scopes
    h4 = compute_plan_hash(
        CanonicalApprovalPayload(**{**base.model_dump(), "granted_scopes": ["sandbox:create", "data:seed:synthetic"]})
    )
    assert h4 != base_hash

    # 5. Changed action parameters
    h5 = compute_plan_hash(
        CanonicalApprovalPayload(
            **{
                **base.model_dump(),
                "planned_actions": [
                    {
                        "step_id": "step-00000001",
                        "action_type": StepActionType.PROVISION_MOCK_SANDBOX.value,
                        "is_privileged": True,
                        "required_scopes": ["sandbox:create"],
                        "action_parameters": {"memory_mb": 4096},  # Changed param
                    }
                ],
            }
        )
    )
    assert h5 != base_hash

    # 6. Changed synthetic fixtures
    h6 = compute_plan_hash(
        CanonicalApprovalPayload(**{**base.model_dump(), "synthetic_fixtures": ["users.json", "orders.json"]})
    )
    assert h6 != base_hash


def test_extract_canonical_payload_from_setup_plan() -> None:
    """Verify extraction from a SetupPlan into a CanonicalApprovalPayload covers all security fields."""
    step1 = PlannedStep(
        step_id="step-00000001",
        action_type=StepActionType.DISCOVER_REPOSITORY,
        name="Discover",
        description="Inspect files",
        is_privileged=False,
        required_scopes=[PermissionScope.SANDBOX_READ],
        action_parameters={"depth": 2},
    )
    step2 = PlannedStep(
        step_id="step-00000002",
        action_type=StepActionType.PROVISION_MOCK_SANDBOX,
        name="Provision",
        description="Spin up container",
        is_privileged=True,
        required_scopes=[PermissionScope.SANDBOX_CREATE],
        action_parameters={"timeout": 60},
    )

    plan = SetupPlan(
        plan_id="plan-999",
        request_id="req-888",
        plan_version=1,
        target_environment="local-sandbox",
        steps=[step1, step2],
        estimated_duration_seconds=30,
        created_at=datetime.now(timezone.utc),
        canonical_plan_hash="0" * 64,
    )

    payload = extract_canonical_payload_from_plan(
        plan,
        granted_scopes=["sandbox:create", "sandbox:read"],
        synthetic_fixtures=["fixtures.json"],
    )

    assert payload.request_id == "req-888"
    assert payload.target_environment == "local-sandbox"
    assert payload.plan_version == 1
    assert payload.granted_scopes == ["sandbox:create", "sandbox:read"]
    assert len(payload.planned_actions) == 2
    assert payload.planned_actions[0]["step_id"] == "step-00000001"
    assert payload.planned_actions[1]["action_type"] == "PROVISION_MOCK_SANDBOX"
    assert payload.synthetic_fixtures == ["fixtures.json"]

    plan_hash = compute_plan_hash(payload)
    assert len(plan_hash) == 64
