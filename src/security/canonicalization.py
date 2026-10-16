"""RFC 8785 JSON Canonicalization Scheme (JCS) and plan hashing service."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any
import rfc8785
from pydantic import BaseModel

from src.core.exceptions import CanonicalizationError
from src.models.plans import CanonicalApprovalPayload, SetupPlan


@dataclass(frozen=True)
class CanonicalizationResult:
    """Immutable result of RFC 8785 canonical serialization and SHA-256 digest computation."""

    canonical_bytes: bytes
    canonical_text: str
    sha256_digest: str


def _validate_and_sanitize(obj: Any) -> Any:
    """
    Recursively validate that values conform to strict JSON standards.
    Rejects NaN, Infinity, -Infinity, sets, or complex objects.
    Preserves Unicode code points exactly as supplied without NFC/NFD normalization.
    """
    if isinstance(obj, BaseModel):
        # Convert model to raw dict preserving types
        return _validate_and_sanitize(obj.model_dump(mode="json"))

    if isinstance(obj, dict):
        # Validate all keys are strings
        out_dict: dict[str, Any] = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"RFC 8785 requires all object keys to be strings; received key {k!r} of type {type(k).__name__}")
            out_dict[k] = _validate_and_sanitize(v)
        return out_dict

    if isinstance(obj, (list, tuple)):
        return [_validate_and_sanitize(item) for item in obj]

    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise CanonicalizationError(f"RFC 8785 strictly forbids NaN and Infinity values; received: {obj}")
        return obj

    if isinstance(obj, (int, str, bool)) or obj is None:
        return obj

    raise CanonicalizationError(f"Unsupported data type for RFC 8785 canonicalization: {type(obj).__name__}")


def canonicalize(data: Any) -> CanonicalizationResult:
    """
    Serialize an arbitrary object or Pydantic model according to RFC 8785 (JSON Canonicalization Scheme).

    Rules enforced:
    1. UTF-8 output without BOM.
    2. Zero Unicode normalization (RFC 8785 Section 3.2.2: code points preserved exactly as supplied).
    3. Property ordering lexicographically sorted by UTF-16 code units (RFC 8785 Section 3.2.3).
    4. Strict ECMAScript number serialization (no trailing zeros, integers formatted without decimals).
    5. Escaping strictly limited to quote, backslash, and control characters U+0000..U+001F.
    6. Rejection of NaN, Infinity, and non-string object keys.

    Args:
        data: Primitive Python structure or Pydantic model to canonicalize.

    Returns:
        CanonicalizationResult containing canonical UTF-8 bytes, decoded text, and lowercase SHA-256 hex digest.

    Raises:
        CanonicalizationError: If payload contains invalid or unsupported types.
    """
    try:
        sanitized = _validate_and_sanitize(data)
        canonical_bytes = rfc8785.dumps(sanitized)
        canonical_text = canonical_bytes.decode("utf-8")
        sha256_digest = hashlib.sha256(canonical_bytes).hexdigest()
        return CanonicalizationResult(
            canonical_bytes=canonical_bytes,
            canonical_text=canonical_text,
            sha256_digest=sha256_digest,
        )
    except (rfc8785.CanonicalizationError, rfc8785.FloatDomainError, rfc8785.IntegerDomainError) as err:
        raise CanonicalizationError(f"RFC 8785 canonical serialization failed: {err}") from err
    except CanonicalizationError:
        raise
    except Exception as exc:
        raise CanonicalizationError(f"Unexpected canonicalization error: {exc}") from exc


def extract_canonical_payload_from_plan(
    plan: SetupPlan,
    granted_scopes: list[str],
    synthetic_fixtures: list[str] | None = None,
) -> CanonicalApprovalPayload:
    """
    Extract the security-relevant subset from a SetupPlan into a CanonicalApprovalPayload.

    Covers all security-relevant fields:
    - request_id
    - target_environment
    - plan_version
    - granted_scopes (sorted)
    - planned_actions (step_id, action_type, is_privileged, required_scopes, action_parameters)
    - synthetic_fixtures (sorted)

    Args:
        plan: The ordered setup plan.
        granted_scopes: List of scope strings approved for this plan.
        synthetic_fixtures: Optional list of fixture identifiers allowed for seeding.

    Returns:
        CanonicalApprovalPayload instance ready for canonical serialization and signing.
    """
    planned_actions: list[dict[str, Any]] = []
    auto_fixtures: list[str] = []
    for step in plan.steps:
        planned_actions.append(
            {
                "step_id": step.step_id,
                "action_type": step.action_type.value,
                "is_privileged": step.is_privileged,
                "required_scopes": [s.value for s in step.required_scopes],
                "action_parameters": step.action_parameters,
            }
        )
        if step.action_type.value == "SEED_SYNTHETIC_DATA":
            auto_fixtures = step.action_parameters.get("fixtures", [])

    fixtures = synthetic_fixtures if synthetic_fixtures is not None else auto_fixtures

    return CanonicalApprovalPayload(
        request_id=plan.request_id,
        target_environment=plan.target_environment,
        plan_version=plan.plan_version,
        granted_scopes=granted_scopes,
        planned_actions=planned_actions,
        synthetic_fixtures=fixtures,
    )


def compute_plan_hash(payload: CanonicalApprovalPayload | SetupPlan | dict[str, Any]) -> str:
    """
    Compute the deterministic lowercase 64-character SHA-256 fingerprint of a plan or approval payload.

    Args:
        payload: CanonicalApprovalPayload, SetupPlan, or primitive dict.

    Returns:
        Hexadecimal SHA-256 string.
    """
    if isinstance(payload, SetupPlan):
        # Default extraction assuming plan scopes
        all_scopes = sorted({s.value for step in payload.steps for s in step.required_scopes})
        payload = extract_canonical_payload_from_plan(payload, granted_scopes=all_scopes)

    result = canonicalize(payload)
    return result.sha256_digest
