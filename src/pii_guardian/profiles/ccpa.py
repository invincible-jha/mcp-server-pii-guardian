# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
CCPA / CPRA personal information classification profile.

Implements personal information (PI) categorisation aligned with:
- Cal. Civ. Code § 1798.140(v) — CCPA personal information definition
- Cal. Civ. Code § 1798.121    — CPRA sensitive personal information (SPI)

The CCPA defines "personal information" as information that identifies,
relates to, describes, or is reasonably capable of being associated with
a particular consumer or household.

The CPRA (2020) added a subset called "sensitive personal information"
which consumers have an additional right to limit the use of.

All dataclasses are frozen; this module carries no mutable state.

Usage:
    profile = CCPAProfile.default()
    category = profile.classify_pi("EMAIL_ADDRESS")
    sensitive = profile.is_sensitive_pi(category)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pii_guardian.types import RedactionStrategy


class CCPACategory(str, Enum):
    """
    CCPA / CPRA personal information categories.

    IDENTIFIERS   — Real name, alias, postal address, email, account name,
                    SSN, DL, passport number, IP, or other similar identifiers.
    COMMERCIAL     — Records of products/services purchased, obtained, considered.
    BIOMETRIC      — Physiological, biological, or behavioural characteristics.
    INTERNET       — Browsing history, search history, interaction with
                    websites, applications, or advertisements.
    GEOLOCATION    — Precise geolocation data.
    EMPLOYMENT     — Professional or employment-related information.
    EDUCATION      — Education information per FERPA.
    INFERENCES     — Profiles drawn from PI to reflect preferences,
                    characteristics, psychological trends, predispositions,
                    behaviour, attitudes, intelligence, abilities, and aptitudes.
    """

    IDENTIFIERS = "identifiers"
    COMMERCIAL = "commercial"
    BIOMETRIC = "biometric"
    INTERNET = "internet"
    GEOLOCATION = "geolocation"
    EMPLOYMENT = "employment"
    EDUCATION = "education"
    INFERENCES = "inferences"


# CPRA sensitive PI designation: categories that are "sensitive personal information"
# under Cal. Civ. Code § 1798.121 — consumers may direct businesses to limit use.
_SENSITIVE_CATEGORIES: frozenset[CCPACategory] = frozenset({
    CCPACategory.BIOMETRIC,
    CCPACategory.GEOLOCATION,
})

# Under CPRA, specific IDENTIFIERS fields are also sensitive PI:
#   SSN, DL, passport, financial account, precise geolocation, racial/ethnic origin,
#   religious beliefs, union membership, contents of mail/email/texts, and health/sex.
# We surface this distinction per entity type in the entity index below.
_SENSITIVE_IDENTIFIER_ENTITY_TYPES: frozenset[str] = frozenset({
    "US_SSN",
    "US_DRIVER_LICENSE",
    "PASSPORT",
    "BANK_ACCOUNT",
    "CREDIT_CARD",
    "BIOMETRIC",
    "RELIGION",
    "TRADE_UNION",
    "SEXUAL_ORIENTATION",
    "US_MEDICARE_BENEFICIARY",
})


@dataclass(frozen=True)
class CCPACategoryConfig:
    """Configuration for a single CCPA personal information category.

    Attributes:
        category:           The CCPACategory this config describes.
        entity_types:       Presidio entity labels that map to this category.
        redaction_strategy: How detected PI of this category should be handled.
        ccpa_reference:     The Cal. Civ. Code section that defines this category.
        cpra_sensitive:     True when this category is always sensitive PI under CPRA.
    """

    category: CCPACategory
    entity_types: tuple[str, ...]
    redaction_strategy: RedactionStrategy
    ccpa_reference: str
    cpra_sensitive: bool


# ---------------------------------------------------------------------------
# Category definitions
# ---------------------------------------------------------------------------

_CATEGORY_CONFIGS: tuple[CCPACategoryConfig, ...] = (
    CCPACategoryConfig(
        category=CCPACategory.IDENTIFIERS,
        entity_types=(
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "LOCATION",
            "ADDRESS",
            "US_SSN",
            "US_DRIVER_LICENSE",
            "PASSPORT",
            "IP_ADDRESS",
        ),
        redaction_strategy=RedactionStrategy.MASK,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(A)",
        cpra_sensitive=False,  # individual entity types may be sensitive — see index
    ),
    CCPACategoryConfig(
        category=CCPACategory.COMMERCIAL,
        entity_types=("COMMERCIAL_DATA",),
        redaction_strategy=RedactionStrategy.MASK,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(D)",
        cpra_sensitive=False,
    ),
    CCPACategoryConfig(
        category=CCPACategory.BIOMETRIC,
        entity_types=("BIOMETRIC",),
        redaction_strategy=RedactionStrategy.REMOVE,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(E)",
        cpra_sensitive=True,
    ),
    CCPACategoryConfig(
        category=CCPACategory.INTERNET,
        entity_types=("URL", "INTERNET_DATA"),
        redaction_strategy=RedactionStrategy.MASK,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(F)",
        cpra_sensitive=False,
    ),
    CCPACategoryConfig(
        category=CCPACategory.GEOLOCATION,
        entity_types=("GPS_COORDINATE", "PRECISE_LOCATION"),
        redaction_strategy=RedactionStrategy.REMOVE,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(G)",
        cpra_sensitive=True,
    ),
    CCPACategoryConfig(
        category=CCPACategory.EMPLOYMENT,
        entity_types=("EMPLOYMENT_DATA", "ORGANIZATION"),
        redaction_strategy=RedactionStrategy.MASK,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(I)",
        cpra_sensitive=False,
    ),
    CCPACategoryConfig(
        category=CCPACategory.EDUCATION,
        entity_types=("EDUCATION_DATA",),
        redaction_strategy=RedactionStrategy.MASK,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(J)",
        cpra_sensitive=False,
    ),
    CCPACategoryConfig(
        category=CCPACategory.INFERENCES,
        entity_types=("INFERRED_DATA",),
        redaction_strategy=RedactionStrategy.REMOVE,
        ccpa_reference="Cal. Civ. Code § 1798.140(v)(1)(K)",
        cpra_sensitive=False,
    ),
)

# Reverse index: entity_type -> CCPACategory
_ENTITY_TO_CATEGORY: dict[str, CCPACategory] = {}
for _cfg in _CATEGORY_CONFIGS:
    for _et in _cfg.entity_types:
        _ENTITY_TO_CATEGORY[_et] = _cfg.category


# ---------------------------------------------------------------------------
# Public profile class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CCPAProfile:
    """CCPA / CPRA personal information classification profile.

    Classifies Presidio entity types against the personal information
    categories defined in Cal. Civ. Code § 1798.140(v) and flags sensitive
    personal information as designated by the CPRA.

    Attributes:
        category_configs:   Tuple of all active CCPACategoryConfig entries.
        default_category:   Fallback category for entity types not explicitly
                            listed in any config.
    """

    category_configs: tuple[CCPACategoryConfig, ...] = field(
        default_factory=lambda: _CATEGORY_CONFIGS
    )
    default_category: CCPACategory = CCPACategory.IDENTIFIERS

    @classmethod
    def default(cls) -> CCPAProfile:
        """Return the standard CCPA/CPRA profile covering all PI categories."""
        return cls()

    def classify_pi(self, entity_type: str) -> CCPACategory:
        """Map *entity_type* to its CCPA personal information category.

        Parameters
        ----------
        entity_type:
            A Presidio entity label such as ``"EMAIL_ADDRESS"`` or ``"BIOMETRIC"``.

        Returns
        -------
        CCPACategory:
            The applicable CCPA category.  Falls back to IDENTIFIERS for
            unknown entity types.
        """
        return _ENTITY_TO_CATEGORY.get(entity_type, self.default_category)

    def is_sensitive_pi(self, category: CCPACategory) -> bool:
        """Return True when *category* is Sensitive Personal Information under CPRA.

        Parameters
        ----------
        category:
            The CCPACategory to test.

        Returns
        -------
        bool:
            True when consumers have the right to limit use under
            Cal. Civ. Code § 1798.121.
        """
        return category in _SENSITIVE_CATEGORIES

    def is_sensitive_identifier(self, entity_type: str) -> bool:
        """Return True when *entity_type* is a sensitive identifier under CPRA.

        Certain IDENTIFIERS-category entity types (SSN, passport, financial
        accounts, biometric, etc.) are Sensitive PI even though the broad
        IDENTIFIERS category is not marked as wholly sensitive.

        Parameters
        ----------
        entity_type:
            A Presidio entity label.

        Returns
        -------
        bool:
            True when the entity type is in the CPRA sensitive identifier set.
        """
        return entity_type in _SENSITIVE_IDENTIFIER_ENTITY_TYPES

    def redaction_strategy_for(self, entity_type: str) -> RedactionStrategy:
        """Return the configured RedactionStrategy for *entity_type*.

        Parameters
        ----------
        entity_type:
            A Presidio entity label.

        Returns
        -------
        RedactionStrategy:
            The strategy to apply.  Defaults to MASK for unrecognised types.
        """
        category = _ENTITY_TO_CATEGORY.get(entity_type)
        if category is None:
            return RedactionStrategy.MASK
        for cfg in self.category_configs:
            if cfg.category == category:
                return cfg.redaction_strategy
        return RedactionStrategy.MASK

    def sensitive_categories(self) -> list[CCPACategory]:
        """Return all CCPACategory values designated as Sensitive PI under CPRA."""
        return [cat for cat in CCPACategory if cat in _SENSITIVE_CATEGORIES]
