"""Execute installed security scanners and normalize their JSON reports.

The runner deliberately uses subprocess with explicit argument lists rather than
shell strings. Scanner binaries must be installed by the caller/CI environment.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from scanners.bandit_parser import parse_bandit_output
from scanners.trivy_parser import parse_trivy_output
from scanners.zap_parser import parse_zap_output
from scanners.finding_schema import Finding


class ScannerExecutionError(RuntimeError):
    """Raised when a scanner cannot be executed or produces invalid output."""


def _run(command: list[str], output_path: str, allowed_return_codes: set[int]) -> None:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode not in allowed_return_codes:
        stderr = result.stderr.strip() or result.stdout.strip()
        raise ScannerExecutionError(
            f"Scanner command failed ({result.returncode}): {' '.join(command)}\n{stderr}"
        )
    if not Path(output_path).exists():
        raise ScannerExecutionError(f"Scanner completed but did not create {output_path}")


def run_bandit(target: str, output_path: str) -> list[Finding]:
    """Run Bandit and parse its JSON report."""
    _run(["bandit", "-r", target, "-f", "json", "-o", output_path], output_path, {0, 1, 2})
    return parse_bandit_output(output_path)


def run_trivy(target: str, output_path: str, target_type: str = "fs") -> list[Finding]:
    """Run Trivy against a filesystem or image and parse its JSON report."""
    if target_type not in {"fs", "image", "rootfs", "repo"}:
        raise ValueError("target_type must be one of: fs, image, rootfs, repo")
    _run(["trivy", target_type, "--format", "json", "--output", output_path, target], output_path, {0, 1})
    return parse_trivy_output(output_path)


def run_zap_baseline(target_url: str, output_path: str) -> list[Finding]:
    """Run OWASP ZAP's baseline scan against an HTTP(S) target."""
    _run(
        ["zap-baseline.py", "-t", target_url, "-J", output_path, "-I"],
        output_path,
        {0, 1, 2},
    )
    return parse_zap_output(output_path)


def run_scanners(
    *,
    bandit_target: str | None = None,
    trivy_target: str | None = None,
    trivy_target_type: str = "fs",
    zap_target_url: str | None = None,
    output_dir: str = "reports/scans",
) -> list[Finding]:
    """Run every requested scanner and return one normalized finding list."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    findings: list[Finding] = []

    if bandit_target:
        findings.extend(run_bandit(bandit_target, str(directory / "bandit.json")))
    if trivy_target:
        findings.extend(run_trivy(trivy_target, str(directory / "trivy.json"), trivy_target_type))
    if zap_target_url:
        findings.extend(run_zap_baseline(zap_target_url, str(directory / "zap.json")))

    return findings
