from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Finding:
    category: str
    label: str
    risk: str
    detail: str = ""


@dataclass
class ScanResult:
    path: Path
    file_type: str
    findings: List[Finding] = field(default_factory=list)
    cleanable: bool = True
    removed_bytes: int = 0
    error: Optional[str] = None

    @property
    def highest_risk(self) -> str:
        if self.error:
            return "none"
        return max(
            (item.risk for item in self.findings),
            key=lambda value: RISK_ORDER[value],
            default="none",
        )

