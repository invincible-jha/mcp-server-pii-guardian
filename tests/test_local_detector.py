# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for LocalPIIDetector — pure regex-based PII detection.

No external dependencies (presidio, spacy) are required for these tests
because LocalPIIDetector is a standalone, import-free module.
"""

from __future__ import annotations

import pytest

from pii_guardian.local_detector import DetectorConfig, LocalPIIDetector, PIIFinding


class TestPIIFinding:
    def test_valid_finding_construction(self) -> None:
        finding = PIIFinding(
            entity_type="EMAIL_ADDRESS",
            text="alice@example.com",
            start=0,
            end=17,
            confidence=0.85,
        )
        assert finding.entity_type == "EMAIL_ADDRESS"
        assert finding.confidence == 0.85

    def test_confidence_must_be_between_0_and_1(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            PIIFinding(entity_type="EMAIL_ADDRESS", text="x", start=0, end=1, confidence=1.5)

    def test_start_must_be_non_negative(self) -> None:
        with pytest.raises(ValueError, match="start"):
            PIIFinding(entity_type="EMAIL_ADDRESS", text="x", start=-1, end=1, confidence=0.9)

    def test_end_must_be_gte_start(self) -> None:
        with pytest.raises(ValueError, match="end"):
            PIIFinding(entity_type="EMAIL_ADDRESS", text="x", start=5, end=4, confidence=0.9)

    def test_finding_is_frozen(self) -> None:
        finding = PIIFinding(
            entity_type="PHONE_NUMBER", text="555-1234", start=0, end=8, confidence=0.8
        )
        with pytest.raises((AttributeError, TypeError)):
            finding.entity_type = "EMAIL_ADDRESS"  # type: ignore[misc]


class TestDetectorConfig:
    def test_all_patterns_class_method_creates_config_with_no_filter(self) -> None:
        config = DetectorConfig.all_patterns()
        # all_patterns sets empty enabled_patterns = all enabled
        assert len(config.enabled_patterns) == 0

    def test_min_confidence_default_is_0_7(self) -> None:
        config = DetectorConfig()
        assert config.min_confidence == 0.7

    def test_custom_min_confidence_is_accepted(self) -> None:
        config = DetectorConfig(min_confidence=0.9)
        assert config.min_confidence == 0.9


class TestLocalPIIDetector:
    def test_default_constructor_enables_all_patterns(self) -> None:
        detector = LocalPIIDetector()
        assert len(detector.active_pattern_names) > 0

    def test_detects_email_address(self) -> None:
        detector = LocalPIIDetector()
        findings = detector.detect("Please email us at support@example.com for help.")
        email_findings = [f for f in findings if f.entity_type == "EMAIL_ADDRESS"]
        assert len(email_findings) >= 1
        assert "support@example.com" in [f.text for f in email_findings]

    def test_detects_us_ssn(self) -> None:
        detector = LocalPIIDetector()
        findings = detector.detect("My SSN is 123-45-6789.")
        ssn_findings = [f for f in findings if f.entity_type == "US_SSN"]
        assert len(ssn_findings) >= 1

    def test_detects_phone_number(self) -> None:
        detector = LocalPIIDetector()
        findings = detector.detect("Call me at (555) 867-5309 anytime.")
        phone_findings = [f for f in findings if f.entity_type == "PHONE_NUMBER"]
        assert len(phone_findings) >= 1

    def test_detects_ip_address(self) -> None:
        detector = LocalPIIDetector()
        findings = detector.detect("The server IP is 192.168.1.100.")
        ip_findings = [f for f in findings if f.entity_type == "IP_ADDRESS"]
        assert len(ip_findings) >= 1

    def test_returns_empty_list_for_clean_text(self) -> None:
        detector = LocalPIIDetector()
        findings = detector.detect("The quick brown fox jumps over the lazy dog.")
        assert len(findings) == 0

    def test_returns_empty_list_for_empty_string(self) -> None:
        detector = LocalPIIDetector()
        findings = detector.detect("")
        assert len(findings) == 0

    def test_finding_text_is_substring_of_input(self) -> None:
        detector = LocalPIIDetector()
        text = "Contact: alice@example.com"
        findings = detector.detect(text)
        for finding in findings:
            assert text[finding.start:finding.end] == finding.text

    def test_confidence_is_within_valid_range_for_all_findings(self) -> None:
        detector = LocalPIIDetector()
        findings = detector.detect("SSN: 987-65-4320, Email: bob@example.com")
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0

    def test_enabled_patterns_filter_limits_detection(self) -> None:
        config = DetectorConfig(enabled_patterns={"email"}, min_confidence=0.5)
        detector = LocalPIIDetector(config)
        findings = detector.detect("SSN: 123-45-6789, Email: test@example.com")
        entity_types = {f.entity_type for f in findings}
        # Only EMAIL_ADDRESS should be found
        assert "US_SSN" not in entity_types
        assert "EMAIL_ADDRESS" in entity_types

    def test_min_confidence_filters_low_confidence_findings(self) -> None:
        high_confidence_config = DetectorConfig.all_patterns(min_confidence=0.95)
        detector_high = LocalPIIDetector(high_confidence_config)
        low_confidence_config = DetectorConfig.all_patterns(min_confidence=0.1)
        detector_low = LocalPIIDetector(low_confidence_config)

        text = "SSN: 123-45-6789, Phone: 555-867-5309"
        high_findings = detector_high.detect(text)
        low_findings = detector_low.detect(text)
        # Lower threshold should produce >= as many results
        assert len(low_findings) >= len(high_findings)

    def test_detects_credit_card_via_luhn(self) -> None:
        detector = LocalPIIDetector()
        # Luhn-valid test card: 4539 1488 0343 6467
        findings = detector.detect("Card: 4539148803436467")
        cc_findings = [f for f in findings if f.entity_type == "CREDIT_CARD"]
        assert len(cc_findings) >= 1

    def test_does_not_flag_invalid_credit_card(self) -> None:
        detector = LocalPIIDetector()
        # Luhn-invalid: 4539148803436468 (last digit changed)
        findings = detector.detect("Number: 4539148803436468")
        cc_findings = [f for f in findings if f.entity_type == "CREDIT_CARD"]
        assert len(cc_findings) == 0
