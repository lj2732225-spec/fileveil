import struct
import zlib
from pathlib import Path

from .models import Finding, ScanResult


SIGNATURE = b"\x89PNG\r\n\x1a\n"
METADATA_CHUNKS = {b"eXIf", b"tEXt", b"zTXt", b"iTXt", b"tIME"}
SENSITIVE_KEYS = {
    "author": "medium",
    "creator": "medium",
    "comment": "medium",
    "location": "high",
    "gps": "high",
    "device": "medium",
    "camera": "medium",
    "software": "low",
}


def _chunks(data: bytes):
    if not data.startswith(SIGNATURE):
        raise ValueError("Not a PNG file")
    offset = len(SIGNATURE)
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("Truncated PNG chunk")
        chunk_type = data[offset + 4 : offset + 8]
        yield chunk_type, offset, end, data[offset + 8 : offset + 8 + length]
        offset = end
        if chunk_type == b"IEND":
            return
    raise ValueError("PNG has no IEND chunk")


def _text_key(chunk_type: bytes, payload: bytes) -> str:
    if chunk_type == b"tEXt":
        return payload.split(b"\x00", 1)[0].decode("latin1", "replace")
    if chunk_type in (b"zTXt", b"iTXt"):
        return payload.split(b"\x00", 1)[0].decode("latin1", "replace")
    return ""


def inspect(data: bytes, path: Path) -> ScanResult:
    findings = []
    try:
        for chunk_type, _, _, payload in _chunks(data):
            if chunk_type not in METADATA_CHUNKS:
                continue
            if chunk_type == b"eXIf":
                findings.append(Finding("Exif", "EXIF metadata", "high"))
            elif chunk_type == b"tIME":
                findings.append(Finding("Timestamp", "last-modified time", "medium"))
            else:
                key = _text_key(chunk_type, payload)
                risk = SENSITIVE_KEYS.get(key.lower(), "low")
                findings.append(Finding("PNG text", key or "text metadata", risk))
    except (ValueError, struct.error, zlib.error):
        return ScanResult(path, "png", error="Unreadable PNG")
    return ScanResult(path, "png", findings=findings)


def clean(data: bytes) -> bytes:
    output = bytearray(SIGNATURE)
    for chunk_type, start, end, _ in _chunks(data):
        if chunk_type not in METADATA_CHUNKS:
            output.extend(data[start:end])
        if chunk_type == b"IEND":
            return bytes(output)
    raise ValueError("PNG has no IEND chunk")

