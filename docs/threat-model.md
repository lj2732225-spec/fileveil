# Threat model

## Protected against

- Accidental disclosure of EXIF GPS coordinates and capture details in JPEG.
- Basic identifying metadata in PNG text chunks and EXIF.
- Author, editor, company, timestamps, custom fields, and thumbnail metadata in
  modern Office documents.
- Hidden bytes appended after a JPEG end marker.
- Accidentally modifying the original input file.

## Not protected against

- Visible faces, names, screens, addresses, or other content in pixels or text.
- Metadata in unsupported formats, including PDF, HEIC, TIFF, MP4, and legacy
  Office formats.
- Embedded images or relationships outside the explicitly inspected document
  metadata and thumbnail path.
- Steganography or encrypted payloads.
- A compromised operating system or a malicious file exploiting the application
  used to open it after cleaning.
- An adversary who already has the original file.

## Safety rule

For high-risk sharing, inspect the cleaned file visually and use a trusted
sandbox or dedicated device. FileVeil reduces a common source of accidental
disclosure; it does not prove that a document is anonymous.

