import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanners.trivy_parser import parse_trivy_output
from scanners.zap_parser import parse_zap_output


def test_trivy_parser_normalizes_vulnerability():
    findings = parse_trivy_output(str(ROOT / "samples" / "trivy_raw_output.json"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "trivy-0001"
    assert finding.source == "trivy"
    assert finding.raw_severity == "HIGH"
    assert finding.cwe_id == 79
    assert finding.file_path == "python:3.11"
    assert "1.0.2" in finding.description


def test_zap_parser_normalizes_alert_instance():
    findings = parse_zap_output(str(ROOT / "samples" / "zap_raw_output.json"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "zap-0001"
    assert finding.source == "zap"
    assert finding.raw_severity == "HIGH"
    assert finding.cwe_id == 79
    assert "q" in finding.file_path
    assert "Encode untrusted output" in finding.description
