# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PCI DSS cardholder data classification profile.

Implements the two-tier PCI DSS data sensitivity model:

- CHD  (Cardholder Data)              — may be stored if encrypted and access-controlled
- SAD  (Sensitive Authentication Data) — must NEVER be stored after authorisation,
                                         even in encrypted form

PAN masking follows PCI DSS requirement 3.4: the first six and last four digits
are the maximum allowable display.  All other CHD/SAD masking rules are
applied at the strictest permissible level.

Reference: PCI DSS v4.0, Requirement 3 — Protect Stored Account Data

All dataclasses are frozen.

Usage:
    profile = PCIProfile.default()
    level = profile.classify_payment_data("CREDIT_CARD")
    masked = profile.mask_pan("4111111111111111")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pii_guardian.types import RedactionStrategy


class PCISensitivityLevel(str, Enum):
    """
    PCI DSS data sensitivity classification.

    CHD — Cardholder Data.  May be stored if protected; PAN must be masked
          when displayed.
    SAD — Sensitive Authentication Data.  Must never be stored post-auth,
          regardless of encryption.  Always fully redacted.
    """

    CHD = "chd"
    SAD = "sad"


@dataclass(frozen=True)
class PCIDataElementConfig:
    """Configuration for a single PCI DSS data element.

    Attributes:
        label:              Human-readable PCI DSS element name.
        entity_types:       Presidio entity labels that map to this element.
        sensitivity:        CHD or SAD classification.
        redaction_strategy: Redaction strategy to apply on detection.
        storage_permitted:  True when PCI DSS permits storage (CHD only, with
                            encryption).  Always False for SAD.
        display_rule:       Human-readable display/masking rule from the standard.
        pci_requirement:    The PCI DSS requirement reference for this element.
    """

    label: str
    entity_types: tuple[str, ...]
    sensitivity: PCISensitivityLevel
    redaction_strategy: RedactionStrategy
    storage_permitted: bool
    display_rule: str
    pci_requirement: str


# ---------------------------------------------------------------------------
# PCI DSS element definitions
# ---------------------------------------------------------------------------

_PCI_ELEMENTS: tuple[PCIDataElementConfig, ...] = (
    PCIDataElementConfig(
        label="PAN",
        entity_types=("CREDIT_CARD",),
        sensitivity=PCISensitivityLevel.CHD,
        redaction_strategy=RedactionStrategy.MASK,
        storage_permitted=True,
        display_rule="Show first 6 and last 4 digits only; mask remaining digits",
        pci_requirement="PCI DSS v4.0 Req 3.3.1",
    ),
    PCIDataElementConfig(
        label="cardholder_name",
        entity_types=("PERSON",),
        sensitivity=PCISensitivityLevel.CHD,
        redaction_strategy=RedactionStrategy.MASK,
        storage_permitted=True,
        display_rule="May be displayed; mask in logs",
        pci_requirement="PCI DSS v4.0 Req 3.3",
    ),
    PCIDataElementConfig(
        label="expiry_date",
        entity_types=("CREDIT_CARD_EXPIRY",),
        sensitivity=PCISensitivityLevel.CHD,
        redaction_strategy=RedactionStrategy.MASK,
        storage_permitted=True,
        display_rule="May be stored; mask in display contexts",
        pci_requirement="PCI DSS v4.0 Req 3.3",
    ),
    PCIDataElementConfig(
        label="service_code",
        entity_types=("CREDIT_CARD_SERVICE_CODE",),
        sensitivity=PCISensitivityLevel.CHD,
        redaction_strategy=RedactionStrategy.REMOVE,
        storage_permitted=True,
        display_rule="Do not display; remove from all output",
        pci_requirement="PCI DSS v4.0 Req 3.3",
    ),
    PCIDataElementConfig(
        label="CVV",
        entity_types=("CREDIT_CARD_CVV", "CVV"),
        sensitivity=PCISensitivityLevel.SAD,
        redaction_strategy=RedactionStrategy.REMOVE,
        storage_permitted=False,
        display_rule="Never display; must not be stored post-authorisation",
        pci_requirement="PCI DSS v4.0 Req 3.2.1",
    ),
    PCIDataElementConfig(
        label="PIN",
        entity_types=("CREDIT_CARD_PIN", "PIN"),
        sensitivity=PCISensitivityLevel.SAD,
        redaction_strategy=RedactionStrategy.REMOVE,
        storage_permitted=False,
        display_rule="Never display; must not be stored in any form",
        pci_requirement="PCI DSS v4.0 Req 3.2.1",
    ),
)

# Reverse index: entity_type -> PCIDataElementConfig
_ENTITY_TO_CONFIG: dict[str, PCIDataElementConfig] = {}
for _elem in _PCI_ELEMENTS:
    for _et in _elem.entity_types:
        _ENTITY_TO_CONFIG[_et] = _elem


# ---------------------------------------------------------------------------
# PAN masking helper
# ---------------------------------------------------------------------------


def _mask_pan(pan: str) -> str:
    """Apply PCI DSS first-6 / last-4 masking to a PAN string.

    Digits outside the first-6 / last-4 window are replaced with ``*``.
    Non-digit characters (spaces, hyphens) are preserved in position.

    Parameters
    ----------
    pan:
        The raw PAN string, which may contain spaces or hyphens as separators.

    Returns
    -------
    str:
        The masked PAN.  Returns the original string unchanged if it contains
        fewer than 10 digit characters (too short to apply the rule safely).
    """
    digits_only = [ch for ch in pan if ch.isdigit()]
    if len(digits_only) < 10:
        return pan

    masked_digits = list(digits_only)
    for index in range(6, len(masked_digits) - 4):
        masked_digits[index] = "*"

    result_chars: list[str] = []
    digit_cursor = 0
    for ch in pan:
        if ch.isdigit():
            result_chars.append(masked_digits[digit_cursor])
            digit_cursor += 1
        else:
            result_chars.append(ch)

    return "".join(result_chars)


# ---------------------------------------------------------------------------
# Public profile class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PCIProfile:
    """PCI DSS cardholder data classification profile.

    Covers the six PCI DSS data elements across the CHD and SAD tiers.
    PAN masking follows the first-6 / last-4 display rule from PCI DSS
    Requirement 3.3.1.

    Attributes:
        element_configs:    Tuple of all active PCIDataElementConfig entries.
    """

    element_configs: tuple[PCIDataElementConfig, ...] = field(
        default_factory=lambda: _PCI_ELEMENTS
    )

    @classmethod
    def default(cls) -> PCIProfile:
        """Return the standard PCI DSS profile covering all six data elements."""
        return cls()

    def classify_payment_data(self, entity_type: str) -> PCISensitivityLevel | None:
        """Map *entity_type* to its PCI DSS sensitivity level.

        Parameters
        ----------
        entity_type:
            A Presidio entity label such as ``"CREDIT_CARD"`` or ``"CVV"``.

        Returns
        -------
        PCISensitivityLevel | None:
            The sensitivity level, or None if the entity type is not recognised
            as a PCI DSS data element.
        """
        config = _ENTITY_TO_CONFIG.get(entity_type)
        return config.sensitivity if config is not None else None

    def redaction_strategy_for(self, entity_type: str) -> RedactionStrategy:
        """Return the configured RedactionStrategy for *entity_type*.

        Parameters
        ----------
        entity_type:
            A Presidio entity label.

        Returns
        -------
        RedactionStrategy:
            REMOVE for unrecognised types (safe default for payment context).
        """
        config = _ENTITY_TO_CONFIG.get(entity_type)
        return config.redaction_strategy if config is not None else RedactionStrategy.REMOVE

    def mask_pan(self, pan: str) -> str:
        """Apply PCI DSS first-6 / last-4 PAN masking.

        Parameters
        ----------
        pan:
            The raw PAN string to mask.

        Returns
        -------
        str:
            The masked PAN string.
        """
        return _mask_pan(pan)

    def sad_entity_types(self) -> list[str]:
        """Return all Presidio entity types classified as SAD (never store)."""
        result: list[str] = []
        for config in self.element_configs:
            if config.sensitivity == PCISensitivityLevel.SAD:
                result.extend(config.entity_types)
        return result

    def chd_entity_types(self) -> list[str]:
        """Return all Presidio entity types classified as CHD (store with protection)."""
        result: list[str] = []
        for config in self.element_configs:
            if config.sensitivity == PCISensitivityLevel.CHD:
                result.extend(config.entity_types)
        return result
