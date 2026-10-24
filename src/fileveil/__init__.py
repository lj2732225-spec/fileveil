"""FileVeil: local, copy-only removal of hidden file metadata."""

__version__ = "0.1.0"

from .api import clean_file, discover_files, scan_file

__all__ = ["clean_file", "discover_files", "scan_file"]

