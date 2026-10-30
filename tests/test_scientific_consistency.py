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
    """Verify hermetic isolation, environment metadata, SBOM, and individual trial telemetry."""
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

    # 2. Verification of environmental isolation, version match & full SBOM inventory (FASE C.1)
    for rel_name, rel_data in [("3.12.0", r12), ("3.15.0", r15)]:
        env_meta = rel_data.get("environment_metadata", {})
        assert env_meta.get("isolated_venv") is True, f"Virtualenv for {rel_name} must be isolated"
        assert env_meta.get("system_site_packages_inherited") is False, f"Virtualenv for {rel_name} must not inherit system packages"
        assert env_meta.get("pip_check_passed") is True, f"Pip check must pass for {rel_name}"
        assert env_meta.get("mlflow_version_requested") == rel_name, f"Requested version mismatch for {rel_name}"
        assert env_meta.get("mlflow_version_verified") == rel_name, f"Verified version mismatch for {rel_name}"
        assert env_meta.get("installed_packages_count", 0) > 0, f"Package count missing for {rel_name}"

    # 3. Verification of per-trial granular telemetry (FASE C.2)
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

def _parse_markdown_table_cells(md_content: str) -> dict[str, tuple[str, str]]:
    """
    Parses the Markdown benchmark table into a dictionary mapping row headers
    to (cell_col1, cell_col2).
    """
    table_rows = {}
    lines = md_content.splitlines()
    in_table = False
    for line in lines:
        if "| Parametro Statistico |" in line:
            in_table = True
            continue
        if in_table:
            stripped = line.strip()
            if not stripped.startswith("|"):
                break
            parts = [p.strip() for p in stripped.split("|")]
            # Format: ['', Header, Col1, Col2, '']
            if len(parts) >= 4 and not parts[1].startswith(":-") and not parts[1].startswith(":--"):
                header = parts[1]
                col1 = parts[2]
                col2 = parts[3]
                table_rows[header] = (col1, col2)
    return table_rows

def _extract_single_float(cell: str) -> float:
    match = re.search(r"([0-9]+\.[0-9]+)", cell)
    assert match is not None, f"Could not extract float from cell: {cell}"
    return float(match.group(1))

def _extract_two_floats(cell: str) -> tuple[float, float]:
    matches = re.findall(r"([0-9]+\.[0-9]+)", cell)
    assert len(matches) >= 2, f"Expected 2 floats in cell '{cell}', found {matches}"
    return float(matches[0]), float(matches[1])

def test_json_and_markdown_statistical_reconciliation():
    """
    Verify 100% numerical consistency cell-by-cell between JSON telemetry
    and the Markdown benchmark table in FINAL_SECURITY_AND_SCIENTIFIC_AUDIT.md.
    """
    assert MD_REPORT_PATH.exists(), f"Missing required markdown audit report: {MD_REPORT_PATH}"
    
    json_data = json.loads(JSON_REPORT_PATH.read_text(encoding="utf-8"))
    md_text = MD_REPORT_PATH.read_text(encoding="utf-8")
    
    b12 = json_data["MLflow_3_12_0_Official_Release"]["benchmark"]
    b15 = json_data["MLflow_3_15_0_Official_Release"]["benchmark"]
    
    rows = _parse_markdown_table_cells(md_text)
    assert len(rows) >= 8, f"Benchmark table not properly parsed; found rows: {list(rows.keys())}"
    
    # 1. Exact cell-by-cell float assertions
    metric_map = {
        "**Tempo Medio**": "mean_ms",
        "**Media Troncata (10%)**": "trimmed_mean_10pct_ms",
        "**Mediana (p50)**": "median_ms",
        "**Range Interquartile (IQR)**": "iqr_ms",
        "**95° Percentile (p95)**": "p95_ms",
        "**99° Percentile (p99)**": "p99_ms",
        "**Deviazione Standard**": "std_ms"
    }
    
    for row_header, json_key in metric_map.items():
        assert row_header in rows, f"Row header '{row_header}' missing from Markdown table"
        cell12, cell15 = rows[row_header]
        val12 = _extract_single_float(cell12)
        val15 = _extract_single_float(cell15)
        
        expected12 = float(b12[json_key])
        expected15 = float(b15[json_key])
        
        assert val12 == pytest.approx(expected12, abs=1e-3), (
            f"Mismatch in cell {row_header} for MLflow 3.12: table={val12}, json={expected12}"
        )
        assert val15 == pytest.approx(expected15, abs=1e-3), (
            f"Mismatch in cell {row_header} for MLflow 3.15: table={val15}, json={expected15}"
        )

    # 2. Min / Max row assertion
    assert "**Min / Max**" in rows, "Row '**Min / Max**' missing from Markdown table"
    min12, max12 = _extract_two_floats(rows["**Min / Max**"][0])
    min15, max15 = _extract_two_floats(rows["**Min / Max**"][1])
    assert min12 == pytest.approx(float(b12["min_ms"]), abs=1e-3)
    assert max12 == pytest.approx(float(b12["max_ms"]), abs=1e-3)
    assert min15 == pytest.approx(float(b15["min_ms"]), abs=1e-3)
    assert max15 == pytest.approx(float(b15["max_ms"]), abs=1e-3)

    # 3. Section D.3 latency explanation difference assertion
    expected_diff = round(abs(float(b12["mean_ms"]) - float(b15["mean_ms"])), 3)
    diff_pattern = rf"La differenza di circa ([0-9\.]+) ms tra le due versioni"
    diff_match = re.search(diff_pattern, md_text)
    assert diff_match is not None, "Latency difference explanation missing in Section D.3"
    assert float(diff_match.group(1)) == pytest.approx(expected_diff, abs=1e-2), (
        f"Section D.3 latency difference mismatch: text={diff_match.group(1)}, expected={expected_diff}"
    )
