# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
GDPR personal data classification profile.

Implements PII categorisation aligned with:
- GDPR Article 4    — definition of personal data
- GDPR Article 9    — special categories of personal data
- GDPR Article 10   — personal data relating to criminal convictions
- GDPR Articles 6 and 9 — lawful bases for processing

All dataclasses are frozen; this module carries no mutable state.

Usage:
    profile = GDPRProfile.default()
    category = profile.classify_pii_finding("EMAIL_ADDRESS")
    bases = get_required_legal_basis(category)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pii_guardian.types import RedactionStrategy


class GDPRDataCategory(str, Enum):
    """
    High-level GDPR classification for a piece of personal data.

    STANDARD_PERSONAL — ordinary personal data under Article 4.
    SPECIAL_CATEGORY  — special category data under Article 9, requiring
                        explicit consent or another specific Art 9(2) basis.
    CRIMINAL          — data relating to criminal convictions and offences
                        under Article 10, controlled by member-state law.
    """

    STANDARD_PERSONAL = "standard_personal"
    SPECIAL_CATEGORY = "special_category"
    CRIMINAL = "criminal"


@dataclass(frozen=True)
class GDPRCategoryConfig:
    """Configuration for a single GDPR personal data category.

    Attributes:
        entity_types:       Presidio entity labels that map to this category.
        gdpr_data_category: GDPR classification (standard / special / criminal).
        redaction_strategy: How detected data of this category should be redacted.
        retention_period:   Operator-defined retention period label (e.g. "30d",
                            "7y").  This is a documentation field only — the
                            library does not enforce retention automatically.
        article_reference:  The GDPR article that governs this category.
    """

    entity_types: tuple[str, ...]
    gdpr_data_category: GDPRDataCategory
    redaction_strategy: RedactionStrategy
    retention_period: str
    article_reference: str


# ---------------------------------------------------------------------------
# Category definitions — keyed by a human-readable label
# ---------------------------------------------------------------------------

_CATEGORY_CONFIGS: dict[str, GDPRCategoryConfig] = {
    "name": GDPRCategoryConfig(
        entity_types=("PERSON",),
        gdpr_data_category=GDPRDataCategory.STANDARD_PERSONAL,
        redaction_strategy=RedactionStrategy.MASK,
        retention_period="operator-defined",
        article_reference="Art. 4(1)",
    ),
    "email": GDPRCategoryConfig(
        entity_types=("EMAIL_ADDRESS",),
        gdpr_data_category=GDPRDataCategory.STANDARD_PERSONAL,
        redaction_strategy=RedactionStrategy.MASK,
        retention_period="operator-defined",
        article_reference="Art. 4(1)",
    ),
    "phone": GDPRCategoryConfig(
        entity_types=("PHONE_NUMBER",),
        gdpr_data_category=GDPRDataCategory.STANDARD_PERSONAL,
        redaction_strategy=RedactionStrategy.MASK,
        retention_period="operator-defined",
        article_reference="Art. 4(1)",
    ),
    "address": GDPRCategoryConfig(
        entity_types=("LOCATION", "ADDRESS"),
        gdpr_data_category=GDPRDataCategory.STANDARD_PERSONAL,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 4(1)",
    ),
    "national_id": GDPRCategoryConfig(
        entity_types=("US_SSN", "US_DRIVER_LICENSE", "UK_NHS", "NATIONAL_ID"),
        gdpr_data_category=GDPRDataCategory.STANDARD_PERSONAL,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 4(1)",
    ),
    "health_data": GDPRCategoryConfig(
        entity_types=("MEDICAL_LICENSE", "US_MEDICARE_BENEFICIARY",),
        gdpr_data_category=GDPRDataCategory.SPECIAL_CATEGORY,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 9(1)",
    ),
    "biometric_data": GDPRCategoryConfig(
        entity_types=("BIOMETRIC",),
        gdpr_data_category=GDPRDataCategory.SPECIAL_CATEGORY,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 9(1)",
    ),
    "genetic_data": GDPRCategoryConfig(
        entity_types=("GENETIC",),
        gdpr_data_category=GDPRDataCategory.SPECIAL_CATEGORY,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 9(1)",
    ),
    "political_opinions": GDPRCategoryConfig(
        entity_types=("POLITICAL_OPINION",),
        gdpr_data_category=GDPRDataCategory.SPECIAL_CATEGORY,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 9(1)",
    ),
    "religious_beliefs": GDPRCategoryConfig(
        entity_types=("RELIGION",),
        gdpr_data_category=GDPRDataCategory.SPECIAL_CATEGORY,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 9(1)",
    ),
    "trade_union_membership": GDPRCategoryConfig(
        entity_types=("TRADE_UNION",),
        gdpr_data_category=GDPRDataCategory.SPECIAL_CATEGORY,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 9(1)",
    ),
    "sexual_orientation": GDPRCategoryConfig(
        entity_types=("SEXUAL_ORIENTATION",),
        gdpr_data_category=GDPRDataCategory.SPECIAL_CATEGORY,
        redaction_strategy=RedactionStrategy.REMOVE,
        retention_period="operator-defined",
        article_reference="Art. 9(1)",
    ),
}

# Reverse index: entity_type string -> GDPRDataCategory
_ENTITY_TYPE_INDEX: dict[str, GDPRDataCategory] = {}
for _cfg in _CATEGORY_CONFIGS.values():
    for _et in _cfg.entity_types:
        _ENTITY_TYPE_INDEX[_et] = _cfg.gdpr_data_category

# ---------------------------------------------------------------------------
# Lawful-basis tables (Art. 6 and Art. 9)
# ---------------------------------------------------------------------------

_ARTICLE_6_BASES: list[str] = [
    "Art. 6(1)(a) — Consent",
    "Art. 6(1)(b) — Contract performance",
    "Art. 6(1)(c) — Legal obligation",
    "Art. 6(1)(d) — Vital interests",
    "Art. 6(1)(e) — Public task",
    "Art. 6(1)(f) — Legitimate interests",
]

_ARTICLE_9_BASES: list[str] = [
    "Art. 9(2)(a) — Explicit consent",
    "Art. 9(2)(b) — Employment / social security obligations",
    "Art. 9(2)(c) — Vital interests (data subject incapacitated)",
    "Art. 9(2)(d) — Not-for-profit body (members/former members)",
    "Art. 9(2)(e) — Data manifestly made public by data subject",
    "Art. 9(2)(f) — Legal claims establishment/defence",
    "Art. 9(2)(g) — Substantial public interest (member-state law)",
    "Art. 9(2)(h) — Healthcare / social care purposes",
    "Art. 9(2)(i) — Public health",
    "Art. 9(2)(j) — Archiving / research / statistics (public interest)",
]

_ARTICLE_10_BASES: list[str] = [
    "Art. 10 — Official authority control only",
    "Art. 10 — Member-state law authorisation required",
]


def get_required_legal_basis(category: GDPRDataCategory) -> list[str]:
    """Return the applicable lawful-basis options for *category*.

    Parameters
    ----------
    category:
        The GDPR data category for which bases are sought.

    Returns
    -------
    list[str]:
        Human-readable strings naming each applicable lawful basis under
        GDPR Articles 6, 9, or 10.  The operator must select one that
        applies to their specific processing activity.
    """
    match category:
        case GDPRDataCategory.STANDARD_PERSONAL:
            return list(_ARTICLE_6_BASES)
        case GDPRDataCategory.SPECIAL_CATEGORY:
            return list(_ARTICLE_9_BASES)
        case GDPRDataCategory.CRIMINAL:
            return list(_ARTICLE_10_BASES)


# ---------------------------------------------------------------------------
# Public profile class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GDPRProfile:
    """GDPR personal data classification profile.

    Classifies Presidio entity types against GDPR Article 4 personal data
    and Article 9 special categories.  The profile is intentionally
    read-only — compliance configuration is set at construction time and
    never mutated at runtime.

    Attributes:
        category_configs:   Mapping of human-readable category label to its
                            GDPRCategoryConfig definition.
        default_category:   Fallback category for entity types not explicitly
                            listed in any config.
    """

    category_configs: dict[str, GDPRCategoryConfig] = field(
        default_factory=lambda: dict(_CATEGORY_CONFIGS)
    )
    default_category: GDPRDataCategory = GDPRDataCategory.STANDARD_PERSONAL

    @classmethod
    def default(cls) -> GDPRProfile:
        """Return the standard GDPR profile covering all Article 4 categories."""
        return cls()

    def classify_pii_finding(self, entity_type: str) -> GDPRDataCategory:
        """Map a Presidio *entity_type* label to its GDPR data category.

        Parameters
        ----------
        entity_type:
            A Presidio entity label such as ``"EMAIL_ADDRESS"`` or ``"US_SSN"``.

        Returns
        -------
        GDPRDataCategory:
            The applicable GDPR category.  Falls back to STANDARD_PERSONAL
            for unknown entity types.
        """
        return _ENTITY_TYPE_INDEX.get(entity_type, self.default_category)

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
        for config in self.category_configs.values():
            if entity_type in config.entity_types:
                return config.redaction_strategy
        return RedactionStrategy.REMOVE

    def category_labels(self) -> list[str]:
        """Return all configured category label names."""
        return list(self.category_configs.keys())

    def configs_for_gdpr_category(
        self, gdpr_category: GDPRDataCategory
    ) -> list[GDPRCategoryConfig]:
        """Return all category configs that belong to *gdpr_category*.

        Parameters
        ----------
        gdpr_category:
            The GDPR classification to filter by.

        Returns
        -------
        list[GDPRCategoryConfig]:
            All configs whose gdpr_data_category matches.
        """
        return [
            cfg
            for cfg in self.category_configs.values()
            if cfg.gdpr_data_category == gdpr_category
        ]
