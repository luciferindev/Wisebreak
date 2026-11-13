"""Knox / Android-management knowledge base loader and policy analyzer.

This module is DOCUMENTATION-ONLY. It explains how management technologies
enforce restrictions and which legitimate administrative mechanisms control
them. It never contacts Knox admin APIs, never fabricates management access,
and never attempts to remove or bypass management.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..paths import resource_path

KB_FILE = "data/knox_kb.json"


@dataclass(slots=True)
class RestrictionExplanation:
    key: str
    observed: str
    likely_policies: list[str]
    legitimate_control: str
    not_an_exploit: bool

    @property
    def title(self) -> str:
        return self.key.replace("_", " ").title()


class KnoxKnowledge:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @classmethod
    def load(cls) -> "KnoxKnowledge":
        path = Path(resource_path(KB_FILE))
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(data)

    # ---- technologies -----------------------------------------------------
    @property
    def disclaimer(self) -> str:
        return self._data.get("disclaimer", "")

    def technologies(self) -> list[dict[str, Any]]:
        return list(self._data.get("technologies", []))

    def technology(self, tech_id: str) -> dict[str, Any] | None:
        for t in self.technologies():
            if t["id"] == tech_id:
                return t
        return None

    def compare(self, id_a: str, id_b: str) -> dict[str, Any]:
        """Return a side-by-side comparison of two technologies."""
        a, b = self.technology(id_a), self.technology(id_b)
        if a is None or b is None:
            return {"error": f"unknown technology id(s): {id_a}, {id_b}"}
        return {
            "a": a["name"],
            "b": b["name"],
            "category_a": a["category"],
            "category_b": b["category"],
            "removal_a": a["removal"],
            "removal_b": b["removal"],
            "controls_a": a["controls"],
            "controls_b": b["controls"],
        }

    # ---- restriction analysis --------------------------------------------
    def restriction_explanations(self) -> list[RestrictionExplanation]:
        out = []
        for key, val in self._data.get("restriction_explanations", {}).items():
            out.append(
                RestrictionExplanation(
                    key=key,
                    observed=val.get("observed", ""),
                    likely_policies=val.get("likely_policies", []),
                    legitimate_control=val.get("legitimate_control", ""),
                    not_an_exploit=bool(val.get("not_an_exploit", True)),
                )
            )
        return out

    def explain_restriction(self, key: str) -> RestrictionExplanation | None:
        for exp in self.restriction_explanations():
            if exp.key == key:
                return exp
        return None

    def analyze_observed(self, restrictions: dict[str, str]) -> list[dict[str, Any]]:
        """Given observed restrictions (key -> status), return explanations.

        ``restrictions`` is e.g. ``{"apk_installation": "blocked", ...}``.
        Only restrictions reported as blocked/disabled are explained.
        """
        results: list[dict[str, Any]] = []
        active = {"blocked", "disabled", "restricted", "not_detected"}
        for key, status in restrictions.items():
            if status.lower() not in active:
                continue
            exp = self.explain_restriction(key)
            if exp is None:
                results.append(
                    {
                        "restriction": key,
                        "status": status,
                        "explanation": "No documented explanation in the KB for this key.",
                    }
                )
                continue
            results.append(
                {
                    "restriction": key,
                    "status": status,
                    "observed": exp.observed,
                    "likely_policies": exp.likely_policies,
                    "legitimate_control": exp.legitimate_control,
                    "not_an_exploit": exp.not_an_exploit,
                }
            )
        return results

    # ---- ownership guidance ----------------------------------------------
    def ownership_guidance(self) -> dict[str, Any]:
        return self._data.get("ownership_guidance", {})
