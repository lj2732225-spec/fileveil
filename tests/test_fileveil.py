import io
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from fileveil import clean_file, scan_file
from fileveil.models import RISK_ORDER


def jpeg_with_exif():
    make = b"Canon\x00"
    tiff = bytearray(b"II\x2a\x00\x08\x00\x00\x00")
    tiff += struct.pack("<H", 1)
    tiff += struct.pack("<HHI", 0x010F, 2, len(make))
    tiff += struct.pack("<I", 26)
    tiff += struct.pack("<I", 0)
    tiff += make
    app1 = b"Exif\x00\x00" + bytes(tiff)
    return (
        b"\xff\xd8"
        + b"\xff\xe1"
        + struct.pack(">H", len(app1) + 2)
        + app1
        + b"\xff\xda\x00\x02\x01\x00"
        + b"\xff\xd9"
        + b"hidden"
    )


def png_chunk(kind, payload):
    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def png_with_text():
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00")
        + png_chunk(b"tEXt", b"Author\x00Alice")
        + png_chunk(b"IEND", b"")
    )


def ooxml_with_metadata():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(
            "docProps/core.xml",
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Alice</dc:creator>'
            "</cp:coreProperties>",
        )
        archive.writestr(
            "docProps/app.xml",
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            "<Company>Example Org</Company></Properties>",
        )
        archive.writestr("word/document.xml", "<document/>")
    return buffer.getvalue()


class FileVeilTests(unittest.TestCase):
    def test_jpeg_scan_and_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "photo.jpg"
            output = Path(folder) / "clean.jpg"
            source.write_bytes(jpeg_with_exif())
            result = scan_file(source)
            self.assertIn("camera make", [item.label for item in result.findings])
            clean_file(source, output)
            cleaned = scan_file(output)
            self.assertEqual(cleaned.findings, [])
            self.assertNotIn(b"Canon", output.read_bytes())
            self.assertNotIn(b"hidden", output.read_bytes())

    def test_png_scan_and_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "image.png"
            output = Path(folder) / "clean.png"
            source.write_bytes(png_with_text())
            result = scan_file(source)
            self.assertEqual(result.highest_risk, "medium")
            clean_file(source, output)
            self.assertEqual(scan_file(output).findings, [])
            self.assertNotIn(b"Alice", output.read_bytes())

    def test_office_scan_and_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "report.docx"
            output = Path(folder) / "clean.docx"
            source.write_bytes(ooxml_with_metadata())
            labels = [item.label for item in scan_file(source).findings]
            self.assertIn("author", labels)
            self.assertIn("company", labels)
            clean_file(source, output)
            self.assertEqual(scan_file(output).findings, [])
            with zipfile.ZipFile(output) as archive:
                self.assertNotIn(b"Alice", archive.read("docProps/core.xml"))
                self.assertNotIn(b"Example Org", archive.read("docProps/app.xml"))

    def test_refuses_to_overwrite_source(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "image.png"
            source.write_bytes(png_with_text())
            with self.assertRaises(ValueError):
                clean_file(source, source)

    def test_risk_order_is_complete(self):
        self.assertEqual(set(RISK_ORDER), {"none", "low", "medium", "high"})


if __name__ == "__main__":
    unittest.main()

