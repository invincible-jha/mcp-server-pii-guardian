# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Standard PII test corpus for benchmarking pii_guardian detection quality.

Each corpus entry is a (text, expected_detections) pair where expected_detections
is a list of (entity_type, span_text) tuples representing the ground-truth PII spans
that should be detected.

This corpus covers the most common PII types and includes both clean positives
and hard negatives (similar-looking text that is NOT PII).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CorpusEntry:
    """A single benchmark sample with ground-truth annotations.

    Attributes:
        text:            The raw text to scan.
        expected_types:  Set of entity_type strings expected to be found.
        expected_spans:  List of (entity_type, span_text) ground-truth pairs.
        is_negative:     True when no PII should be detected (hard negative).
        description:     Human-readable label for reporting.
    """

    text: str
    expected_types: frozenset[str]
    expected_spans: list[tuple[str, str]]
    is_negative: bool = False
    description: str = ""


# ---------------------------------------------------------------------------
# Email address corpus
# ---------------------------------------------------------------------------

EMAIL_CORPUS: list[CorpusEntry] = [
    CorpusEntry(
        text="Please contact support@example.com for help.",
        expected_types=frozenset({"EMAIL_ADDRESS"}),
        expected_spans=[("EMAIL_ADDRESS", "support@example.com")],
        description="simple_email",
    ),
    CorpusEntry(
        text="Send the file to alice.b+tag@sub.domain.co.uk before noon.",
        expected_types=frozenset({"EMAIL_ADDRESS"}),
        expected_spans=[("EMAIL_ADDRESS", "alice.b+tag@sub.domain.co.uk")],
        description="complex_email_with_plus_tag",
    ),
    CorpusEntry(
        text="CC both john@company.org and mary@company.org on the reply.",
        expected_types=frozenset({"EMAIL_ADDRESS"}),
        expected_spans=[
            ("EMAIL_ADDRESS", "john@company.org"),
            ("EMAIL_ADDRESS", "mary@company.org"),
        ],
        description="two_emails_in_one_sentence",
    ),
    CorpusEntry(
        text="The price is 5@10 which equals 50.",
        expected_types=frozenset(),
        expected_spans=[],
        is_negative=True,
        description="negative_email_arithmetic_expression",
    ),
    CorpusEntry(
        text="User@Host is not a valid external address per RFC 5321.",
        expected_types=frozenset(),
        expected_spans=[],
        is_negative=True,
        description="negative_email_no_tld",
    ),
]

# ---------------------------------------------------------------------------
# US Social Security Number corpus
# ---------------------------------------------------------------------------

SSN_CORPUS: list[CorpusEntry] = [
    CorpusEntry(
        text="My Social Security number is 123-45-6789.",
        expected_types=frozenset({"US_SSN"}),
        expected_spans=[("US_SSN", "123-45-6789")],
        description="standard_ssn",
    ),
    CorpusEntry(
        text="SSN: 987-65-4321 — please keep this confidential.",
        expected_types=frozenset({"US_SSN"}),
        expected_spans=[("US_SSN", "987-65-4321")],
        description="ssn_with_label",
    ),
    CorpusEntry(
        text="The ticket reference is 123-45-6789 for tracking.",
        expected_types=frozenset({"US_SSN"}),
        expected_spans=[("US_SSN", "123-45-6789")],
        description="ssn_as_ticket_number_ambiguous",
    ),
    CorpusEntry(
        text="Call 1-800-555-1234 for customer service.",
        expected_types=frozenset({"PHONE_NUMBER"}),
        expected_spans=[("PHONE_NUMBER", "1-800-555-1234")],
        is_negative=True,
        description="negative_ssn_is_phone_number",
    ),
]

# ---------------------------------------------------------------------------
# Phone number corpus
# ---------------------------------------------------------------------------

PHONE_CORPUS: list[CorpusEntry] = [
    CorpusEntry(
        text="Call me at (555) 867-5309 anytime.",
        expected_types=frozenset({"PHONE_NUMBER"}),
        expected_spans=[("PHONE_NUMBER", "(555) 867-5309")],
        description="us_phone_parentheses",
    ),
    CorpusEntry(
        text="My mobile is 555-123-4567 and office is 555-987-6543.",
        expected_types=frozenset({"PHONE_NUMBER"}),
        expected_spans=[
            ("PHONE_NUMBER", "555-123-4567"),
            ("PHONE_NUMBER", "555-987-6543"),
        ],
        description="two_phones",
    ),
    CorpusEntry(
        text="Reach us at +1 555 234 5678 for international callers.",
        expected_types=frozenset({"PHONE_NUMBER"}),
        expected_spans=[("PHONE_NUMBER", "+1 555 234 5678")],
        description="international_us_phone",
    ),
    CorpusEntry(
        text="The meeting is at 9:00 to 10:30 in room 555.",
        expected_types=frozenset(),
        expected_spans=[],
        is_negative=True,
        description="negative_phone_time_and_room",
    ),
]

# ---------------------------------------------------------------------------
# Name corpus (requires NLP — lower confidence expected)
# ---------------------------------------------------------------------------

NAME_CORPUS: list[CorpusEntry] = [
    CorpusEntry(
        text="The patient, John Smith, was admitted on Monday.",
        expected_types=frozenset({"PERSON"}),
        expected_spans=[("PERSON", "John Smith")],
        description="person_name_in_medical_context",
    ),
    CorpusEntry(
        text="Dr. Sarah O'Brien signed the report.",
        expected_types=frozenset({"PERSON"}),
        expected_spans=[("PERSON", "Sarah O'Brien")],
        description="person_name_with_title",
    ),
]

# ---------------------------------------------------------------------------
# Address corpus
# ---------------------------------------------------------------------------

ADDRESS_CORPUS: list[CorpusEntry] = [
    CorpusEntry(
        text="Ship to 123 Main Street, Springfield, IL 62701.",
        expected_types=frozenset({"LOCATION", "US_ZIP_CODE"}),
        expected_spans=[
            ("LOCATION", "123 Main Street, Springfield, IL"),
            ("US_ZIP_CODE", "62701"),
        ],
        description="full_us_mailing_address",
    ),
]

# ---------------------------------------------------------------------------
# Mixed PII corpus (multiple entity types in one text)
# ---------------------------------------------------------------------------

MIXED_CORPUS: list[CorpusEntry] = [
    CorpusEntry(
        text=(
            "Patient: Jane Doe, DOB: 01/15/1985, SSN: 321-54-9876, "
            "Phone: 555-234-5678, Email: jane.doe@health.org"
        ),
        expected_types=frozenset({"PERSON", "US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS"}),
        expected_spans=[
            ("PERSON", "Jane Doe"),
            ("US_SSN", "321-54-9876"),
            ("PHONE_NUMBER", "555-234-5678"),
            ("EMAIL_ADDRESS", "jane.doe@health.org"),
        ],
        description="hipaa_patient_record",
    ),
    CorpusEntry(
        text=(
            "From: ceo@acme.com\n"
            "To: hr@acme.com\n"
            "Re: Employee 99887 — call (212) 555-0100 for details."
        ),
        expected_types=frozenset({"EMAIL_ADDRESS", "PHONE_NUMBER"}),
        expected_spans=[
            ("EMAIL_ADDRESS", "ceo@acme.com"),
            ("EMAIL_ADDRESS", "hr@acme.com"),
            ("PHONE_NUMBER", "(212) 555-0100"),
        ],
        description="email_header_with_phone",
    ),
]

# ---------------------------------------------------------------------------
# Aggregate corpus — everything combined
# ---------------------------------------------------------------------------

ALL_CORPUS: list[CorpusEntry] = (
    EMAIL_CORPUS
    + SSN_CORPUS
    + PHONE_CORPUS
    + NAME_CORPUS
    + ADDRESS_CORPUS
    + MIXED_CORPUS
)

# Subcorpus by entity type for per-type precision/recall measurement
CORPUS_BY_ENTITY_TYPE: dict[str, list[CorpusEntry]] = {
    "EMAIL_ADDRESS": EMAIL_CORPUS,
    "US_SSN": SSN_CORPUS,
    "PHONE_NUMBER": PHONE_CORPUS,
    "PERSON": NAME_CORPUS,
}
