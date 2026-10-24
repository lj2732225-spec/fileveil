# FileVeil

Remove hidden metadata before you share a file.

Photos can reveal where they were taken. Office documents can preserve authors,
organizations, edit times, and custom properties. FileVeil finds those traces,
writes a cleaned copy, and checks the result again. Everything runs locally;
files are never uploaded.

## Why it matters

Metadata is invisible in most previews but can expose people who share:

- photos of their homes, children, or protest sites;
- documents from work or volunteer organizations;
- screenshots and reports sent to journalists or support services;
- research files containing stale author and device identifiers.

The safest workflow should be simple: scan, clean, verify, share.

## Supported files

| Format | Removed or sanitized |
| --- | --- |
| JPEG | EXIF, GPS, XMP, IPTC, comments, trailing data |
| PNG | EXIF, text chunks, compressed text, timestamps |
| DOCX, XLSX, PPTX | Author and editor, timestamps, company, custom properties, thumbnail metadata |

FileVeil preserves image pixels and document content. It does not redact visible
text, blur faces, or detect every possible embedded object. See
[the threat model](docs/threat-model.md) before sharing high-risk material.

## Install

Python 3.9 or newer is required. FileVeil has no runtime dependencies.

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Use

Inspect a file or directory without modifying anything:

```bash
fileveil scan photo.jpg
fileveil scan ./documents
```

Write cleaned copies to a separate directory:

```bash
fileveil clean photo.jpg report.docx -o ./safe
```

Use the exit status in a publishing pipeline:

```bash
fileveil scan ./release-assets --fail-on medium
```

`--fail-on medium` exits with status `2` when the scan finds medium- or
high-risk metadata. Output files are generated with a temporary file and an
atomic rename. Existing outputs are protected unless `--force` is supplied.

[Example output](docs/example-output.txt)

## Design

- **Local-first:** no network access and no telemetry.
- **Copy-only:** the input file is never modified.
- **Verified:** the generated file is scanned again before it is published.
- **Bounded:** archive entry counts and expanded sizes are checked.
- **Auditable:** JSON scan output and optional cleanup manifests are available.

FileVeil is intentionally small enough to audit. The JPEG, PNG, and OOXML
implementations use only the Python standard library.

## Limitations

This is an early project. TIFF, HEIC, MP4, PDF, embedded objects, comments, and
visible content redaction are not yet supported. A clean scan means FileVeil
found none of the metadata it knows how to detect; it is not a guarantee that a
file is anonymous.

## Contribute

Contributions are welcome. Good first contributions include new test fixtures,
format support, documentation, and safer verification logic. Read
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) first.

## License

MIT

