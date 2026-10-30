import json
import re
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT_DIR / "reports"
JSON_REPORT_PATH = REPORTS_DIR / "cve_2026_96804_real_releases_study.json"
MD_REPORT_PATH = REPORTS_DIR / "FINAL_SECURITY_AND_SCIENTIFIC_AUDIT.md"

def test_json_report_exists_and_valid():
    """Verify that the official releases JSON study report exists and is valid JSON."""
    assert JSON_REPORT_PATH.exists(), f"Missing required report: {JSON_REPORT_PATH}"
    data = json.loads(JSON_REPORT_PATH.read_text(encoding="utf-8"))
    
    assert "MLflow_3_12_0_Official_Release" in data
    assert "MLflow_3_15_0_Official_Release" in data
    assert "study_protocol" in data

def test_json_report_scientific_properties():
    """Verify hermetic isolation, individual trial telemetry, and security outcomes."""
    data = json.loads(JSON_REPORT_PATH.read_text(encoding="utf-8"))
    
    r12 = data["MLflow_3_12_0_Official_Release"]
    r15 = data["MLflow_3_15_0_Official_Release"]
    
    # 1. Verification of security states
    assert r12["status"] == "VULNERABILITY_CONFIRMED"
    assert r12["policy_bypassed"] is True
    assert r12["arbitrary_code_executed"] is True
    assert r12["vulnerability_reproduction_rate"] == 1.0
    
    assert r15["status"] == "PATCH_CONFIRMED"
    assert r15["policy_bypassed"] is False
    assert r15["arbitrary_code_executed"] is False
    assert r15["policy_block_rate"] == 1.0

    # 2. Verification of environmental isolation (Fase C.1)
    for rel_name, rel_data in [("3.12.0", r12), ("3.15.0", r15)]:
        env_meta = rel_data.get("environment_metadata", {})
        assert env_meta.get("isolated_venv") is True, f"Virtualenv for {rel_name} must be isolated"
        assert env_meta.get("system_site_packages_inherited") is False, f"Virtualenv for {rel_name} must not inherit system packages"
        assert env_meta.get("pip_check_passed") is True, f"Pip check must pass for {rel_name}"

    # 3. Verification of per-trial granular telemetry (Fase C.2)
    t12 = r12.get("trials_detail", [])
    t15 = r15.get("trials_detail", [])
    assert len(t12) >= 5, "At least 5 trials expected in study report"
    assert len(t15) >= 5, "At least 5 trials expected in study report"
    
    for t in t12:
        assert t["status"] == "LOADED"
        assert t["audit_probe_executed"] is True
        assert t["latency_ms"] > 0
        assert t["audit_trace"] is not None

    for t in t15:
        assert t["status"] == "BLOCKED_BY_POLICY"
        assert t["policy_exception_caught"] is True
        assert t["audit_probe_executed"] is False
        assert t["latency_ms"] > 0
        assert "pickle" in t["exception_detail"].lower() or "disallowed" in t["exception_detail"].lower()

def test_json_and_markdown_statistical_reconciliation():
    """Verify 100% numerical consistency between JSON telemetry and Markdown report (Fase D)."""
    assert MD_REPORT_PATH.exists(), f"Missing required markdown audit report: {MD_REPORT_PATH}"
    
    json_data = json.loads(JSON_REPORT_PATH.read_text(encoding="utf-8"))
    md_text = MD_REPORT_PATH.read_text(encoding="utf-8")
    
    b12 = json_data["MLflow_3_12_0_Official_Release"]["benchmark"]
    b15 = json_data["MLflow_3_15_0_Official_Release"]["benchmark"]
    
    # Assert that benchmark metrics are present in JSON
    for key in ["mean_ms", "trimmed_mean_10pct_ms", "median_ms", "iqr_ms", "p95_ms", "p99_ms", "std_ms"]:
        val12 = str(b12[key])
        val15 = str(b15[key])
        assert val12 in md_text, f"Metric MLflow 3.12 {key}={val12} ms not found in {MD_REPORT_PATH.name}"
        assert val15 in md_text, f"Metric MLflow 3.15 {key}={val15} ms not found in {MD_REPORT_PATH.name}"
