# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
pii_guardian.profiles
=====================

Compliance-specific PII classification profiles.

Each profile maps detected entity types to the categories, sensitivity
levels, and redaction requirements defined by its governing regulation.
All profiles are stateless and constructed from frozen dataclasses —
they carry no mutable state and are safe to share across threads.

Available profiles:
    GDPRProfile     — GDPR Article 4 personal data + Article 9 special categories
    HIPAAProfile    — HIPAA Safe Harbor 18-identifier PHI profile
    PCIProfile      — PCI DSS cardholder and sensitive authentication data
    CCPAProfile     — CCPA / CPRA personal and sensitive personal information
"""

from pii_guardian.profiles.ccpa import CCPACategory, CCPAProfile
from pii_guardian.profiles.gdpr import GDPRDataCategory, GDPRProfile
from pii_guardian.profiles.hipaa import HIPAAProfile, PHIIdentifier
from pii_guardian.profiles.pci import PCIProfile, PCISensitivityLevel

__all__ = [
    "GDPRProfile",
    "GDPRDataCategory",
    "HIPAAProfile",
    "PHIIdentifier",
    "PCIProfile",
    "PCISensitivityLevel",
    "CCPAProfile",
    "CCPACategory",
]
