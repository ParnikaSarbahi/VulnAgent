import sys
from pathlib import Path

# Allow the tests to run from the repository root without requiring an
# editable package install.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanners.deduplicator import deduplicate_findings, fingerprint_finding
from scanners.finding_schema import Finding


def make_finding(**overrides):
    data = {
        "id": "test-1",
        "source": "bandit",
        "title": "[B602] subprocess call with shell=True",
        "description": "subprocess call with shell=True identified",
        "file_path": "app.py",
        "line_number": 42,
        "raw_severity": "HIGH",
        "cwe_id": 78,
        "reference_url": None,
        "code_snippet": "subprocess.run(cmd, shell=True)",
    }
    data.update(overrides)
    return Finding(**data)


def test_same_finding_has_same_fingerprint():
    first = make_finding(id="bandit-0001")
    second = make_finding(id="trivy-0009", source="trivy")

    assert fingerprint_finding(first) == fingerprint_finding(second)


def test_scanner_id_does_not_affect_fingerprint():
    first = make_finding(id="bandit-0001")
    second = make_finding(id="bandit-9999")

    assert fingerprint_finding(first) == fingerprint_finding(second)


def test_whitespace_and_case_are_normalized():
    first = make_finding(title="SQL injection", description="Unsafe query")
    second = make_finding(title="  sql   injection ", description=" unsafe   query ")

    assert fingerprint_finding(first) == fingerprint_finding(second)


def test_different_line_is_not_deduplicated_when_location_is_available():
    first = make_finding(line_number=42)
    second = make_finding(line_number=43)

    assert fingerprint_finding(first) != fingerprint_finding(second)


def test_deduplicate_preserves_first_occurrence():
    first = make_finding(id="first")
    duplicate = make_finding(id="duplicate", source="zap")
    different = make_finding(id="different", cwe_id=89, line_number=99)

    result = deduplicate_findings([first, duplicate, different])

    assert [finding.id for finding in result] == ["first", "different"]
