# Contributing

Thanks for helping make file sharing safer.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

FileVeil targets Python 3.9 and uses no third-party runtime dependencies.

## Pull requests

- Keep changes focused and include tests.
- Explain which metadata can leak and how the change removes it.
- Never weaken the copy-only or post-clean verification guarantees.
- Add or update the threat model when adding a new file format.
- Use only files you are authorized to inspect and redistribute as fixtures.

## Adding a format

Each format needs:

1. Signature and structural validation.
2. A read-only inspector that returns risk-labeled findings.
3. A cleaner that preserves user content.
4. A verification test proving that the cleaned output no longer contains the
   targeted metadata.
5. A documented list of limitations.

Please avoid regex-based rewriting of complex binary formats unless the format
and safety boundaries are clearly documented.

