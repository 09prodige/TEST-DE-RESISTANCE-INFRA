from src.core.scanner import Scanner
from src.core.report import Report


def test_scanner_init(sample_target):
    s = Scanner(sample_target)
    assert s.target == sample_target
    assert s.modules == ["all"]


def test_scanner_run_returns_dict(sample_target):
    s = Scanner(sample_target)
    result = s.run()
    assert isinstance(result, dict)
    assert result["target"] == sample_target


def test_report_to_json(sample_results):
    r = Report(sample_results)
    output = r.to_json()
    assert "generated_at" in output
    assert "example.com" in output


def test_report_save_json(tmp_path, sample_results):
    r = Report(sample_results)
    out = str(tmp_path / "report")
    r.save(out, fmt="json")
    import os
    assert os.path.exists(f"{out}.json")
