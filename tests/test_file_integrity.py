"""
Unit tests for CyberGuard File Integrity Monitoring (FIM) Module.
"""

from pathlib import Path
import pytest

from core.risk_engine import Severity
from modules.file_integrity import FileIntegrityMonitor


def test_baseline_creation_and_persistence(tmp_path: Path):
    """Tests creating and saving a baseline manifest from a directory."""
    dir_a = tmp_path / "monitored"
    dir_a.mkdir()

    f1 = dir_a / "app.conf"
    f2 = dir_a / "users.db"
    f1.write_text("port=8080\nssl=enabled")
    f2.write_text("user:admin:hash123")

    manifest_file = tmp_path / "baseline.json"
    manifest = FileIntegrityMonitor.create_baseline(
        target_path=dir_a,
        algorithm="sha256",
        manifest_save_path=manifest_file,
    )

    assert manifest_file.is_file()
    assert len(manifest.files) == 2
    assert "app.conf" in manifest.files
    assert "users.db" in manifest.files

    # Reload from disk
    loaded = FileIntegrityMonitor.load_baseline(manifest_file)
    assert loaded.root_path == str(dir_a.resolve())
    assert len(loaded.files) == 2
    assert loaded.files["app.conf"].digest == manifest.files["app.conf"].digest


def test_integrity_verification_unmodified(tmp_path: Path):
    """Files that have not changed must verify as completely intact."""
    dir_a = tmp_path / "clean_dir"
    dir_a.mkdir()

    (dir_a / "service.py").write_text("print('running')")
    manifest_file = tmp_path / "clean_baseline.json"

    FileIntegrityMonitor.create_baseline(dir_a, manifest_save_path=manifest_file)
    result = FileIntegrityMonitor.verify_against_baseline(manifest_file, target_path=dir_a)

    assert result.is_intact is True
    assert len(result.verified_files) == 1
    assert len(result.modified_files) == 0
    assert len(result.added_files) == 0
    assert len(result.deleted_files) == 0


def test_integrity_detects_modification_addition_and_deletion(tmp_path: Path):
    """Validates differential detection of modified, added, and deleted files."""
    mon_dir = tmp_path / "diff_test"
    mon_dir.mkdir()

    file_keep = mon_dir / "keep.txt"
    file_mod = mon_dir / "modify.txt"
    file_del = mon_dir / "delete.txt"

    file_keep.write_text("keep this intact")
    file_mod.write_text("original content")
    file_del.write_text("to be deleted")

    manifest_path = tmp_path / "diff_manifest.json"
    FileIntegrityMonitor.create_baseline(mon_dir, manifest_save_path=manifest_path)

    # 1. Modify file_mod
    file_mod.write_text("tampered unauthorized content!")
    # 2. Delete file_del
    file_del.unlink()
    # 3. Add file_add
    file_add = mon_dir / "backdoor.sh"
    file_add.write_text("#!/bin/bash\necho unauthorized")

    result = FileIntegrityMonitor.verify_against_baseline(manifest_path, target_path=mon_dir)

    assert result.is_intact is False
    assert len(result.verified_files) == 1
    assert "keep.txt" in result.verified_files

    assert len(result.modified_files) == 1
    assert result.modified_files[0]["file"] == "modify.txt"

    assert len(result.deleted_files) == 1
    assert "delete.txt" in result.deleted_files

    assert len(result.added_files) == 1
    assert result.added_files[0]["file"] == "backdoor.sh"

    # Convert to findings
    findings = FileIntegrityMonitor.convert_to_findings(result)
    assert len(findings) == 3
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities
    assert Severity.MEDIUM in severities


def test_terminal_report_output_tampered(tmp_path: Path):
    """Ensures formatted terminal output reflects tampering alerts."""
    dir_a = tmp_path / "report_test"
    dir_a.mkdir()
    f = dir_a / "config.ini"
    f.write_text("v1")

    manifest_path = tmp_path / "manifest.json"
    FileIntegrityMonitor.create_baseline(dir_a, manifest_save_path=manifest_path)
    f.write_text("v2_tampered")

    res = FileIntegrityMonitor.verify_against_baseline(manifest_path, target_path=dir_a)
    report_text = FileIntegrityMonitor.format_terminal_report(res)

    assert "WARNING - INTEGRITY TAMPERED" in report_text
    assert "config.ini" in report_text
    assert "Expected:" in report_text
    assert "Current :" in report_text
