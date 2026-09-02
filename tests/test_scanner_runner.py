from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanners.scanner_runner import run_bandit, run_trivy, run_zap_baseline


class Completed:
    returncode = 0
    stdout = ""
    stderr = ""


def test_bandit_runner_uses_json_output(monkeypatch, tmp_path):
    seen = {}

    def fake_run(command, capture_output, text):
        seen["command"] = command
        Path(command[-1]).write_text('{"results": []}', encoding="utf-8")
        return Completed()

    monkeypatch.setattr("scanners.scanner_runner.subprocess.run", fake_run)
    assert run_bandit("src", str(tmp_path / "bandit.json")) == []
    assert seen["command"][:3] == ["bandit", "-r", "src"]
    assert "json" in seen["command"]


def test_trivy_runner_accepts_image_target(monkeypatch, tmp_path):
    seen = {}

    def fake_run(command, capture_output, text):
        seen["command"] = command
        Path(command[command.index("--output") + 1]).write_text(
            '{"Results": []}', encoding="utf-8"
        )
        return Completed()

    monkeypatch.setattr("scanners.scanner_runner.subprocess.run", fake_run)
    assert run_trivy("demo:latest", str(tmp_path / "trivy.json"), "image") == []
    assert seen["command"][:2] == ["trivy", "image"]


def test_zap_runner_uses_baseline_script(monkeypatch, tmp_path):
    seen = {}

    def fake_run(command, capture_output, text):
        seen["command"] = command
        Path(command[command.index("-J") + 1]).write_text(
            '{"site": []}', encoding="utf-8"
        )
        return Completed()

    monkeypatch.setattr("scanners.scanner_runner.subprocess.run", fake_run)
    assert run_zap_baseline("https://example.test", str(tmp_path / "zap.json")) == []
    assert seen["command"][:2] == ["zap-baseline.py", "-t"]
