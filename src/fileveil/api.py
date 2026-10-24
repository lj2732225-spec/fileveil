import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable, List

from . import jpeg, ooxml, png
from .models import ScanResult


SUPPORTED_SUFFIXES = {".jpg", ".jpeg", ".png", ".docx", ".xlsx", ".pptx"}
FORMAT_NAMES = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png"}


def discover_files(paths: Iterable[Path]) -> List[Path]:
    output = []
    seen = set()
    for path in paths:
        candidates = path.rglob("*") if path.is_dir() else [path]
        for candidate in candidates:
            if not candidate.is_file() or candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
                continue
            resolved = candidate.resolve()
            if resolved not in seen:
                output.append(candidate)
                seen.add(resolved)
    return sorted(output)


def _format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".docx", ".xlsx", ".pptx"}:
        return "ooxml"
    return FORMAT_NAMES.get(suffix, "unsupported")


def _inspect(path: Path, data: bytes) -> ScanResult:
    kind = _format(path)
    try:
        if kind == "jpeg":
            return jpeg.inspect(data, path)
        if kind == "png":
            return png.inspect(data, path)
        if kind == "ooxml":
            if not zipfile.is_zipfile(path):
                return ScanResult(path, kind, error="Not a valid Office archive")
            return ooxml.inspect(data, path)
        return ScanResult(path, kind, cleanable=False, error="Unsupported file type")
    except OSError as error:
        return ScanResult(path, kind, error=str(error))


def scan_file(path: Path) -> ScanResult:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as error:
        return ScanResult(path, _format(path), error=str(error))
    return _inspect(path, data)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".fileveil-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def clean_file(
    source: Path, destination: Path, force: bool = False
) -> ScanResult:
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Output must not overwrite the source file")
    if destination.exists() and not force:
        raise FileExistsError(f"Output already exists: {destination}")
    data = source.read_bytes()
    before = _inspect(source, data)
    if before.error:
        raise ValueError(before.error)
    kind = _format(source)
    if kind == "jpeg":
        cleaned = jpeg.clean(data)
    elif kind == "png":
        cleaned = png.clean(data)
    elif kind == "ooxml":
        cleaned = ooxml.clean(data)
    else:
        raise ValueError(f"Unsupported file type: {source.suffix or 'no suffix'}")
    after = _inspect(source, cleaned)
    if after.error or after.findings:
        remaining = ", ".join(item.label for item in after.findings) or after.error
        raise ValueError(f"Verification failed; output not written: {remaining}")
    _atomic_write(destination, cleaned)
    before.removed_bytes = max(0, len(data) - len(cleaned))
    return before


def result_as_dict(result: ScanResult) -> dict:
    return {
        "path": str(result.path),
        "type": result.file_type,
        "cleanable": result.cleanable,
        "highest_risk": result.highest_risk,
        "removed_bytes": result.removed_bytes,
        "error": result.error,
        "findings": [
            {
                "category": item.category,
                "label": item.label,
                "risk": item.risk,
                "detail": item.detail,
            }
            for item in result.findings
        ],
    }


def write_manifest(path: Path, results: List[ScanResult]) -> None:
    payload = json.dumps(
        {"tool": "fileveil", "files": [result_as_dict(item) for item in results]},
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")
    _atomic_write(path, payload + b"\n")

