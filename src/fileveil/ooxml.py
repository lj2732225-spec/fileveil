import io
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from . import jpeg
from .models import Finding, ScanResult


CORE = "docProps/core.xml"
APP = "docProps/app.xml"
CUSTOM = "docProps/custom.xml"
THUMBNAILS = {"docProps/thumbnail.jpeg", "docProps/thumbnail.jpg"}
CORE_FIELDS = {
    "creator": "author",
    "lastModifiedBy": "last editor",
    "created": "creation time",
    "modified": "modification time",
    "title": "title",
    "subject": "subject",
    "description": "description",
    "keywords": "keywords",
    "category": "category",
    "contentStatus": "content status",
    "identifier": "identifier",
    "language": "language",
    "version": "version",
}
APP_FIELDS = {"Company", "Manager", "HyperlinkBase", "Template"}
CORE_EMPTY = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    b'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    b'xmlns:dcterms="http://purl.org/dc/terms/" '
    b'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
    b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>'
)
APP_EMPTY = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
    b'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>'
)
CUSTOM_EMPTY = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" '
    b'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>'
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse(data: bytes):
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return None


def inspect(data: bytes, path: Path) -> ScanResult:
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > 10_000 or sum(item.file_size for item in infos) > 500_000_000:
                return ScanResult(path, "ooxml", error="Archive exceeds safety limits")
            for info in infos:
                if info.filename == CORE:
                    root = _parse(archive.read(info))
                    if root is not None:
                        for element in root.iter():
                            name = _local(element.tag)
                            if name in CORE_FIELDS and (element.text or "").strip():
                                findings.append(
                                    Finding("Document", CORE_FIELDS[name], "medium")
                                )
                elif info.filename == APP:
                    root = _parse(archive.read(info))
                    if root is not None:
                        for element in root.iter():
                            name = _local(element.tag)
                            if name in APP_FIELDS and (element.text or "").strip():
                                findings.append(
                                    Finding("Document", name.lower(), "medium")
                                )
                elif info.filename == CUSTOM:
                    root = _parse(archive.read(info))
                    if root is not None and list(root):
                        findings.append(
                            Finding(
                                "Document",
                                "custom properties",
                                "medium",
                                f"{len(list(root))} entries",
                            )
                        )
                elif info.filename.lower() in THUMBNAILS:
                    result = jpeg.inspect(archive.read(info), path)
                    if result.findings:
                        findings.append(
                            Finding(
                                "Document",
                                "embedded thumbnail metadata",
                                "medium",
                            )
                        )
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return ScanResult(path, "ooxml", error="Unreadable Office document")
    return ScanResult(path, "ooxml", findings=findings)


def _clone_info(source: zipfile.ZipInfo) -> zipfile.ZipInfo:
    target = zipfile.ZipInfo(source.filename, (1980, 1, 1, 0, 0, 0))
    target.compress_type = source.compress_type
    target.external_attr = source.external_attr
    target.internal_attr = source.internal_attr
    target.create_system = source.create_system
    return target


def clean(data: bytes) -> bytes:
    source_buffer = io.BytesIO(data)
    output_buffer = io.BytesIO()
    with zipfile.ZipFile(source_buffer, "r") as source:
        with zipfile.ZipFile(output_buffer, "w") as target:
            for info in source.infolist():
                payload = source.read(info)
                if info.filename == CORE:
                    payload = CORE_EMPTY
                elif info.filename == APP:
                    payload = APP_EMPTY
                elif info.filename == CUSTOM:
                    payload = CUSTOM_EMPTY
                elif info.filename.lower() in THUMBNAILS:
                    payload = jpeg.clean(payload)
                target.writestr(_clone_info(info), payload)
    return output_buffer.getvalue()

