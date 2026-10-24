import struct
from pathlib import Path
from typing import List, Optional, Tuple

from .models import Finding, ScanResult


EXIF_PREFIX = b"Exif\x00\x00"
XMP_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"
PHOTOSHOP_PREFIX = b"Photoshop 3.0\x00"

TAGS = {
    0x010F: "camera make",
    0x0110: "camera model",
    0x0131: "creating software",
    0x0132: "file timestamp",
    0x829A: "shutter speed",
    0x9003: "capture time",
    0x9004: "digitized time",
    0xA431: "camera serial number",
    0xA435: "lens serial number",
    0xC614: "image unique ID",
}
GEOF_TAG = 0x8825
VALUES_PER_TYPE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _u16(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "I", data, offset)[0]


def _ascii_value(data: bytes, offset: int, count: int, endian: str) -> str:
    if offset < 0 or count <= 0 or offset + count > len(data):
        return ""
    raw = data[offset : offset + count].split(b"\x00", 1)[0]
    return raw.decode("utf-8", "replace").strip()


def _read_ifd(
    tiff: bytes, offset: int, endian: str
) -> Tuple[dict, Optional[int]]:
    values = {}
    gps_offset = None
    if offset <= 0 or offset + 2 > len(tiff):
        return values, gps_offset
    count = _u16(tiff, offset, endian)
    for index in range(min(count, 512)):
        entry = offset + 2 + index * 12
        if entry + 12 > len(tiff):
            break
        tag = _u16(tiff, entry, endian)
        value_type = _u16(tiff, entry + 2, endian)
        value_count = _u32(tiff, entry + 4, endian)
        if tag == GEOF_TAG:
            gps_offset = _u32(tiff, entry + 8, endian)
            continue
        name = TAGS.get(tag)
        if not name or value_type not in VALUES_PER_TYPE:
            continue
        total = VALUES_PER_TYPE[value_type] * value_count
        value_offset = entry + 8 if total <= 4 else _u32(tiff, entry + 8, endian)
        if value_type == 2:
            value = _ascii_value(tiff, value_offset, value_count, endian)
            if value:
                values[name] = value
    return values, gps_offset


def exif_findings(payload: bytes) -> List[Finding]:
    output = []
    if not payload.startswith(EXIF_PREFIX) or len(payload) < 14:
        return [Finding("Exif", "EXIF metadata", "medium")]
    tiff = payload[len(EXIF_PREFIX) :]
    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return [Finding("Exif", "EXIF metadata", "medium")]
    try:
        first_ifd = _u32(tiff, 4, endian)
        values, gps_ifd = _read_ifd(tiff, first_ifd, endian)
        if gps_ifd:
            output.append(
                Finding(
                    "Location",
                    "GPS location",
                    "high",
                    "The file may contain where it was captured.",
                )
            )
        for key, value in values.items():
            risk = "high" if "serial" in key or "unique" in key else "medium"
            output.append(Finding("Exif", key, risk, value[:80]))
    except (OSError, struct.error, ValueError):
        output.append(Finding("Exif", "EXIF metadata", "medium"))
    return output or [Finding("Exif", "EXIF metadata", "medium")]


def _segments(data: bytes):
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("Not a JPEG file")
    pos = 2
    while pos < len(data):
        start = pos
        if data[pos] != 0xFF:
            raise ValueError("Malformed JPEG marker")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            raise ValueError("Truncated JPEG")
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            yield marker, start, pos
            return
        if marker == 0x00 or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            yield marker, start, pos
            continue
        if pos + 2 > len(data):
            raise ValueError("Truncated JPEG segment")
        length = int.from_bytes(data[pos : pos + 2], "big")
        end = pos + length
        if length < 2 or end > len(data):
            raise ValueError("Invalid JPEG segment length")
        yield marker, start, end
        pos = end
        if marker == 0xDA:
            return


def inspect(data: bytes, path: Path) -> ScanResult:
    findings = []
    try:
        for marker, start, end in _segments(data):
            raw = data[start:end]
            if marker == 0xE1:
                payload = raw[4:]
                if payload.startswith(EXIF_PREFIX):
                    findings.extend(exif_findings(payload))
                elif payload.startswith(XMP_PREFIX):
                    findings.append(Finding("XMP", "XMP metadata", "medium"))
                else:
                    findings.append(Finding("APP1", "application metadata", "low"))
            elif marker == 0xED:
                findings.append(Finding("IPTC", "Photoshop/IPTC metadata", "medium"))
            elif marker == 0xEC:
                findings.append(Finding("APP12", "application metadata", "low"))
            elif marker == 0xFE:
                findings.append(Finding("Comment", "embedded comment", "medium"))
        eoi = data.rfind(b"\xff\xd9")
        if eoi >= 0 and eoi + 2 < len(data):
            findings.append(
                Finding("Trailing data", "bytes after end of image", "medium")
            )
    except (ValueError, IndexError):
        return ScanResult(path, "jpeg", error="Unreadable JPEG")
    return ScanResult(path, "jpeg", findings=findings)


def clean(data: bytes) -> bytes:
    output = bytearray(b"\xff\xd8")
    eoi_found = False
    for marker, start, end in _segments(data):
        if marker in (0xE1, 0xED, 0xEC, 0xFE):
            continue
        if marker == 0xDA:
            output.extend(data[start:])
            eoi_found = True
            break
        output.extend(data[start:end])
    if not eoi_found:
        raise ValueError("JPEG has no image data")
    eoi = output.rfind(b"\xff\xd9")
    if eoi < 0:
        raise ValueError("JPEG has no end marker")
    return bytes(output[: eoi + 2])

