"""Модели данных для Android Security Analyzer."""
from dataclasses import dataclass
from typing import Optional

@dataclass
class Vulnerability:
    id: str
    severity: str
    cvss_score: float
    category: str
    description: str
    location: str
    recommendation: str
    code_snippet: Optional[str] = None