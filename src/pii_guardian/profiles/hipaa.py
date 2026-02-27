# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
HIPAA Protected Health Information (PHI) classification profile.

Implements the 18-identifier Safe Harbor de-identification standard defined
in 45 CFR § 164.514(b)(2).  Under Safe Harbor, a covered entity may treat
health information as de-identified only when ALL 18 identifier categories
have been removed or sufficiently generalised.

A "limited dataset" profile is also provided: it permits dates and geographic
data at reduced granularity (county-level geography, year-level dates) while
removing the remaining 16 identifiers.

All dataclasses in this module are frozen — the profile carries no mutable
state and is safe to share across threads.

Usage:
    profile = HIPAAProfile.default()
    is_phi = profile.classify_as_phi("EMAIL_ADDRESS")
    required = profile.get_safe_harbor_requirements()
    limited = create_limited_dataset_profile()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pii_guardian.types import RedactionStrategy


class PHIIdentifier(str, Enum):
    """
    The 18 PHI identifier categories from the HIPAA Safe Harbor method.

    Each value maps to one of the identifier types listed in
    45 CFR § 164.514(b)(2)(i).
    """

    NAME = "name"
    ADDRESS = "address"
    DATES = "dates"
    PHONE = "phone"
    FAX = "fax"
    EMAIL = "email"
    SSN = "ssn"
    MRN = "mrn"
    HEALTH_PLAN = "health_plan"
    ACCOUNT = "account"
    LICENSE = "license"
    VEHICLE_ID = "vehicle_id"
    DEVICE_ID = "device_id"
    URL = "url"
    IP = "ip"
    BIOMETRIC = "biometric"
    PHOTO = "photo"
    OTHER_UNIQUE = "other_unique"


@dataclass(frozen=True)
class PHIIdentifierConfig:
    """Configuration for a single Safe Harbor PHI identifier category.

    Attributes:
        identifier:         The PHIIdentifier enum member.
        entity_types:       Presidio entity labels that map to this identifier.
        redaction_strategy: How detected PHI of this type should be handled.
        safe_harbor_remove: True when this identifier must be removed under
                            Safe Harbor.  All 18 are True in the default profile.
        limited_dataset_ok: True when a limited dataset may retain this
                            identifier (only DATES and ADDRESS have this option,
                            subject to granularity restrictions).
        cfr_reference:      The specific 45 CFR section for this identifier.
    """

    identifier: PHIIdentifier
    entity_types: tuple[str, ...]
    redaction_strategy: RedactionStrategy
    safe_harbor_remove: bool
    limited_dataset_ok: bool
    cfr_reference: str


# ---------------------------------------------------------------------------
# Safe Harbor identifier definitions
# ---------------------------------------------------------------------------

_ALL_IDENTIFIERS: tuple[PHIIdentifierConfig, ...] = (
    PHIIdentifierConfig(
        identifier=PHIIdentifier.NAME,
        entity_types=("PERSON",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(A)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.ADDRESS,
        entity_types=("LOCATION", "ADDRESS"),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=True,  # county/state level permitted in limited dataset
        cfr_reference="45 CFR 164.514(b)(2)(i)(B)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.DATES,
        entity_types=("DATE_TIME",),
        redaction_strategy=RedactionStrategy.MASK,
        safe_harbor_remove=True,
        limited_dataset_ok=True,  # year permitted in limited dataset
        cfr_reference="45 CFR 164.514(b)(2)(i)(C)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.PHONE,
        entity_types=("PHONE_NUMBER",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(D)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.FAX,
        entity_types=("FAX_NUMBER",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(E)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.EMAIL,
        entity_types=("EMAIL_ADDRESS",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(F)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.SSN,
        entity_types=("US_SSN",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(G)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.MRN,
        entity_types=("MEDICAL_RECORD_NUMBER", "US_MEDICARE_BENEFICIARY"),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(H)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.HEALTH_PLAN,
        entity_types=("HEALTH_PLAN_BENEFICIARY",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(I)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.ACCOUNT,
        entity_types=("BANK_ACCOUNT",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(J)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.LICENSE,
        entity_types=("US_DRIVER_LICENSE", "MEDICAL_LICENSE"),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(K)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.VEHICLE_ID,
        entity_types=("VEHICLE_IDENTIFICATION_NUMBER",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(L)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.DEVICE_ID,
        entity_types=("DEVICE_IDENTIFIER",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(M)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.URL,
        entity_types=("URL",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(N)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.IP,
        entity_types=("IP_ADDRESS",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(O)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.BIOMETRIC,
        entity_types=("BIOMETRIC",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(P)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.PHOTO,
        entity_types=("PHOTO",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(Q)",
    ),
    PHIIdentifierConfig(
        identifier=PHIIdentifier.OTHER_UNIQUE,
        entity_types=("OTHER_UNIQUE_IDENTIFIER",),
        redaction_strategy=RedactionStrategy.REMOVE,
        safe_harbor_remove=True,
        limited_dataset_ok=False,
        cfr_reference="45 CFR 164.514(b)(2)(i)(R)",
    ),
)

# Reverse index: Presidio entity type -> PHIIdentifier
_ENTITY_TO_PHI: dict[str, PHIIdentifier] = {}
for _cfg in _ALL_IDENTIFIERS:
    for _et in _cfg.entity_types:
        _ENTITY_TO_PHI[_et] = _cfg.identifier


# ---------------------------------------------------------------------------
# Public profile class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HIPAAProfile:
    """HIPAA Safe Harbor PHI classification profile.

    Covers all 18 identifier categories defined in 45 CFR § 164.514(b)(2).
    The profile is read-only — it records which identifiers are active and
    whether this is a full Safe Harbor or limited-dataset configuration.

    Attributes:
        identifier_configs: Tuple of all active PHIIdentifierConfig entries.
        is_limited_dataset: True when this profile represents the limited
                            dataset variant (dates and geography retained at
                            reduced granularity).
    """

    identifier_configs: tuple[PHIIdentifierConfig, ...] = field(
        default_factory=lambda: _ALL_IDENTIFIERS
    )
    is_limited_dataset: bool = False

    @classmethod
    def default(cls) -> HIPAAProfile:
        """Return the full Safe Harbor profile (all 18 identifiers removed)."""
        return cls(identifier_configs=_ALL_IDENTIFIERS, is_limited_dataset=False)

    def classify_as_phi(self, entity_type: str) -> bool:
        """Return True when *entity_type* maps to an active PHI identifier.

        Parameters
        ----------
        entity_type:
            A Presidio entity label such as ``"EMAIL_ADDRESS"`` or ``"US_SSN"``.

        Returns
        -------
        bool:
            True when the entity type is covered by this profile's active
            identifier configs.
        """
        phi_identifier = _ENTITY_TO_PHI.get(entity_type)
        if phi_identifier is None:
            return False
        return any(
            cfg.identifier == phi_identifier for cfg in self.identifier_configs
        )

    def get_safe_harbor_requirements(self) -> list[PHIIdentifier]:
        """Return all PHI identifiers that must be removed under Safe Harbor.

        Returns
        -------
        list[PHIIdentifier]:
            All identifiers in this profile whose safe_harbor_remove flag is True.
        """
        return [
            cfg.identifier
            for cfg in self.identifier_configs
            if cfg.safe_harbor_remove
        ]

    def redaction_strategy_for(self, entity_type: str) -> RedactionStrategy:
        """Return the configured RedactionStrategy for *entity_type*.

        Parameters
        ----------
        entity_type:
            A Presidio entity label.

        Returns
        -------
        RedactionStrategy:
            The strategy to apply.  Defaults to REMOVE for unrecognised types.
        """
        phi_identifier = _ENTITY_TO_PHI.get(entity_type)
        if phi_identifier is None:
            return RedactionStrategy.REMOVE
        for cfg in self.identifier_configs:
            if cfg.identifier == phi_identifier:
                return cfg.redaction_strategy
        return RedactionStrategy.REMOVE


def create_limited_dataset_profile() -> HIPAAProfile:
    """Return a HIPAAProfile for a HIPAA limited dataset.

    In a limited dataset (45 CFR § 164.514(e)), the covered entity may retain:
    - Dates (at year granularity)
    - Geographic data (at county or state level — not street address)

    All other 16 identifiers must still be removed.  This function returns a
    profile whose ``identifier_configs`` excludes the DATES and ADDRESS configs
    so that PII Guardian does not redact those entity types in this context.

    Returns
    -------
    HIPAAProfile:
        A profile with DATES and ADDRESS excluded from active checking,
        and is_limited_dataset set to True.
    """
    limited_configs = tuple(
        cfg
        for cfg in _ALL_IDENTIFIERS
        if cfg.limited_dataset_ok is False
    )
    return HIPAAProfile(identifier_configs=limited_configs, is_limited_dataset=True)
