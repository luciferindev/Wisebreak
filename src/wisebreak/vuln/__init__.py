"""Vulnerability research engine (NVD + advisory sources + matcher)."""

from .nvd import NvdClient, NvdError
from .matcher import (
    PatchLevel,
    compare_patch_levels,
    classify_cve_relevance,
    KNOWN_SOURCES,
)

__all__ = [
    "NvdClient",
    "NvdError",
    "PatchLevel",
    "compare_patch_levels",
    "classify_cve_relevance",
    "KNOWN_SOURCES",
]
