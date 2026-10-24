# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could cause data loss,
metadata leakage, or code execution. Use GitHub's private vulnerability
reporting feature after the repository is published.

Include a minimal affected file or a script that generates one, the observed
behavior, and the affected version.

## Security boundaries

FileVeil is a metadata hygiene tool, not an anonymity system. It does not detect
steganography, visible personal information, embedded objects in every format,
or vulnerabilities in third-party applications that open the generated file.

By design, FileVeil:

- reads input and writes a different destination path;
- runs without network access;
- verifies cleaned output before publishing it;
- refuses to overwrite existing output without an explicit flag.

