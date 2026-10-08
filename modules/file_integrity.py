"""
CyberGuard File Integrity Monitoring (FIM) Module.

Generates cryptographic baseline manifests across directories or files,
detects tampering, modifications, additions, and deletions, and reports risk findings.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from config import DEFAULT_HASH_ALGORITHM
from core.hashing import HashingEngine
from core.logger import get_logger
from core.risk_engine import Finding, Severity

logger = get_logger("modules.file_integrity")


@dataclass
class FileRecord:
    """Metadata and cryptographic checksum for a single baseline file."""
    relative_path: str
    digest: str
    algorithm: str
    size_bytes: int
    modified_iso: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineManifest:
    """Cryptographic baseline manifest snapshot."""
    root_path: str
    algorithm: str
    created_at: str
    files: Dict[str, FileRecord] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_path": self.root_path,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "files": {k: v.to_dict() for k, v in self.files.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineManifest":
        records = {}
        for rel_path, rec in data.get("files", {}).items():
            records[rel_path] = FileRecord(
                relative_path=rec["relative_path"],
                digest=rec["digest"],
                algorithm=rec["algorithm"],
                size_bytes=rec["size_bytes"],
                modified_iso=rec["modified_iso"],
            )
        return cls(
            root_path=data.get("root_path", ""),
            algorithm=data.get("algorithm", DEFAULT_HASH_ALGORITHM),
            created_at=data.get("created_at", ""),
            files=records,
        )


@dataclass
class IntegrityCheckResult:
    """Outcomes of a file integrity evaluation comparing current state to baseline."""
    target_path: str
    algorithm: str
    checked_at: str
    verified_files: List[str] = field(default_factory=list)
    modified_files: List[Dict[str, Any]] = field(default_factory=list)
    added_files: List[Dict[str, Any]] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)

    @property
    def is_intact(self) -> bool:
        """True if no files have been modified, added, or deleted."""
        return not (self.modified_files or self.added_files or self.deleted_files)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "algorithm": self.algorithm,
            "checked_at": self.checked_at,
            "is_intact": self.is_intact,
            "counts": {
                "verified": len(self.verified_files),
                "modified": len(self.modified_files),
                "added": len(self.added_files),
                "deleted": len(self.deleted_files),
            },
            "verified_files": self.verified_files,
            "modified_files": self.modified_files,
            "added_files": self.added_files,
            "deleted_files": self.deleted_files,
        }


class FileIntegrityMonitor:
    """Manages baseline generation, persistent storage, and differential integrity checks."""

    @classmethod
    def create_baseline(
        cls,
        target_path: Union[str, Path],
        algorithm: str = DEFAULT_HASH_ALGORITHM,
        manifest_save_path: Optional[Union[str, Path]] = None,
    ) -> BaselineManifest:
        """
        Recursively scans target file or directory and computes checksum baseline.
        """
        path = Path(target_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Target path does not exist: {path}")

        files_to_hash: List[Path] = []
        if path.is_file():
            files_to_hash.append(path)
            root_dir = path.parent
        else:
            root_dir = path
            for item in sorted(path.rglob("*")):
                if item.is_file() and not item.name.endswith("baseline.json"):
                    files_to_hash.append(item)

        records: Dict[str, FileRecord] = {}
        for f in files_to_hash:
            try:
                rel_path = str(f.relative_to(root_dir))
            except ValueError:
                rel_path = f.name

            digest, _ = HashingEngine.hash_file(f, algorithm=algorithm)
            stat = f.stat()
            modified_iso = datetime.fromtimestamp(stat.st_mtime).isoformat()

            records[rel_path] = FileRecord(
                relative_path=rel_path,
                digest=digest,
                algorithm=algorithm,
                size_bytes=stat.st_size,
                modified_iso=modified_iso,
            )

        manifest = BaselineManifest(
            root_path=str(root_dir),
            algorithm=algorithm,
            created_at=datetime.now().isoformat(),
            files=records,
        )

        if manifest_save_path:
            cls.save_baseline(manifest, manifest_save_path)

        logger.info(
            "Created FIM baseline for %s containing %d files",
            manifest.root_path,
            len(manifest.files),
        )
        return manifest

    @classmethod
    def save_baseline(cls, manifest: BaselineManifest, destination: Union[str, Path]) -> Path:
        """Serializes baseline manifest to JSON file."""
        dest_path = Path(destination).resolve()
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, indent=2)
        logger.info("Saved FIM baseline manifest to %s", dest_path)
        return dest_path

    @classmethod
    def load_baseline(cls, manifest_path: Union[str, Path]) -> BaselineManifest:
        """Loads and deserializes baseline manifest from JSON."""
        path = Path(manifest_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Baseline manifest not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return BaselineManifest.from_dict(data)

    @classmethod
    def verify_against_baseline(
        cls,
        manifest_or_path: Union[BaselineManifest, str, Path],
        target_path: Optional[Union[str, Path]] = None,
    ) -> IntegrityCheckResult:
        """
        Evaluates current filesystem state against baseline.
        Identifies unmodified, modified, added, and deleted files.
        """
        if isinstance(manifest_or_path, BaselineManifest):
            manifest = manifest_or_path
        else:
            manifest = cls.load_baseline(manifest_or_path)

        root = Path(target_path).resolve() if target_path else Path(manifest.root_path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Target directory or file does not exist: {root}")

        # Current files on disk
        current_files: Dict[str, Path] = {}
        if root.is_file():
            rel_name = root.name
            current_files[rel_name] = root
        else:
            for item in sorted(root.rglob("*")):
                if item.is_file() and not item.name.endswith("baseline.json"):
                    try:
                        rel = str(item.relative_to(root))
                    except ValueError:
                        rel = item.name
                    current_files[rel] = item

        verified: List[str] = []
        modified: List[Dict[str, Any]] = []
        added: List[Dict[str, Any]] = []
        deleted: List[str] = []

        # Check existing baseline records
        for rel_path, record in manifest.files.items():
            if rel_path not in current_files:
                deleted.append(rel_path)
            else:
                current_file_path = current_files[rel_path]
                current_digest, _ = HashingEngine.hash_file(
                    current_file_path, algorithm=record.algorithm
                )
                if HashingEngine.compare_hashes(current_digest, record.digest):
                    verified.append(rel_path)
                else:
                    modified.append({
                        "file": rel_path,
                        "expected_hash": record.digest,
                        "current_hash": current_digest,
                        "algorithm": record.algorithm,
                    })

        # Check for added files not in baseline
        for rel_path, file_path in current_files.items():
            if rel_path not in manifest.files:
                digest, _ = HashingEngine.hash_file(file_path, algorithm=manifest.algorithm)
                added.append({
                    "file": rel_path,
                    "current_hash": digest,
                    "algorithm": manifest.algorithm,
                })

        return IntegrityCheckResult(
            target_path=str(root),
            algorithm=manifest.algorithm,
            checked_at=datetime.now().isoformat(),
            verified_files=verified,
            modified_files=modified,
            added_files=added,
            deleted_files=deleted,
        )

    @classmethod
    def convert_to_findings(cls, result: IntegrityCheckResult) -> List[Finding]:
        """Translates integrity discrepancies into risk engine findings."""
        findings: List[Finding] = []

        for mod in result.modified_files:
            findings.append(
                Finding(
                    name=f"Unauthorized File Modification: {mod['file']}",
                    category="File Integrity",
                    severity=Severity.HIGH,
                    description=(
                        f"Checksum mismatch detected on '{mod['file']}'. "
                        f"Expected {mod['algorithm'].upper()} {mod['expected_hash'][:16]}..., "
                        f"found {mod['current_hash'][:16]}..."
                    ),
                    recommendation=(
                        "Inspect file change diffs, verify author authorization, "
                        "and restore from trusted backup if unintended."
                    ),
                    details=mod,
                )
            )

        for add in result.added_files:
            findings.append(
                Finding(
                    name=f"Unexpected File Added: {add['file']}",
                    category="File Integrity",
                    severity=Severity.MEDIUM,
                    description=f"New file '{add['file']}' discovered that is absent from the baseline manifest.",
                    recommendation="Confirm provenance of newly introduced file and update baseline if legitimate.",
                    details=add,
                )
            )

        for rem in result.deleted_files:
            findings.append(
                Finding(
                    name=f"Baseline File Deleted: {rem}",
                    category="File Integrity",
                    severity=Severity.MEDIUM,
                    description=f"File '{rem}' exists in baseline manifest but was deleted or removed from disk.",
                    recommendation="Verify whether file removal was intentional or indicates unauthorized tampering.",
                    details={"file": rem},
                )
            )

        if result.is_intact:
            findings.append(
                Finding(
                    name="File Integrity Fully Verified",
                    category="File Integrity",
                    severity=Severity.INFO,
                    description=f"All {len(result.verified_files)} files match baseline cryptographic signatures.",
                    recommendation="Continue periodic scheduled integrity monitoring.",
                    details={"verified_count": len(result.verified_files)},
                )
            )

        return findings

    @classmethod
    def format_terminal_report(cls, result: IntegrityCheckResult) -> str:
        """Formats the integrity check outcome into clean terminal display."""
        status_line = "INTEGRITY VERIFIED" if result.is_intact else "WARNING - INTEGRITY TAMPERED"
        lines: List[str] = [
            "File Integrity Assessment",
            "==========================",
            f"Target: {result.target_path}",
            f"Algorithm: {result.algorithm.upper()}",
            f"Status: {status_line}",
            "",
            f"Verified files : {len(result.verified_files)}",
            f"Modified files : {len(result.modified_files)}",
            f"Added files    : {len(result.added_files)}",
            f"Deleted files  : {len(result.deleted_files)}",
            "-" * 45,
        ]

        if result.modified_files:
            lines.append("\n⚠️  MODIFIED FILES:")
            for m in result.modified_files:
                lines.append(f"  - {m['file']}")
                lines.append(f"    Expected: {m['expected_hash']}")
                lines.append(f"    Current : {m['current_hash']}")

        if result.added_files:
            lines.append("\n➕ ADDED FILES:")
            for a in result.added_files:
                lines.append(f"  - {a['file']} (Hash: {a['current_hash'][:16]}...)")

        if result.deleted_files:
            lines.append("\n❌ DELETED FILES:")
            for d in result.deleted_files:
                lines.append(f"  - {d}")

        return "\n".join(lines)
