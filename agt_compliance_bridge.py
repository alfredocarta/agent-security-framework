"""Bridge ASF audit events into AGT-backed compliance reporting."""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AGT_SRC_PATH = "/tmp/agt/agent-governance-python/agent-mesh/src"

if AGT_SRC_PATH not in sys.path:
    sys.path.insert(0, AGT_SRC_PATH)


ARTICLE_NAMES = {
    "Art. 9": "Risk management",
    "Art. 12": "Record keeping",
    "Art. 13": "Transparency",
    "Art. 14": "Human oversight",
    "Art. 15": "Accuracy, robustness, and cybersecurity",
}

BLOCKING_MARKERS = {"DENY", "BLOCKED", "KILL_SWITCH", "OUTPUT_BLOCK", "TOOL_BLOCKED"}
ALLOW_MARKERS = {"ALLOWED", "ALLOW", "HEURISTIC_CLEAR", "TOOL_INVOCATION"}
HITL_MARKERS = {"HITL_REQUESTED", "HITL", "HUMAN_OVERSIGHT"}


class AGTComplianceBridge:
    """Generate stable EU AI Act compliance summaries for ASF audit events."""

    def __init__(self):
        self.agt_verified = False
        self.agt_error: str | None = None
        self.agt_engine = None
        self.agt_framework = None
        self.agt_controls: dict[str, Any] = {}
        self.agt_mappings: dict[str, Any] = {}

        try:
            from agentmesh.governance.compliance import ComplianceEngine, ComplianceFramework

            self.agt_framework = ComplianceFramework.EU_AI_ACT
            self.agt_engine = ComplianceEngine(frameworks=[self.agt_framework])
            self.agt_controls = dict(getattr(self.agt_engine, "_controls", {}) or {})
            self.agt_mappings = dict(getattr(self.agt_engine, "_mappings", {}) or {})
            self.agt_verified = True
        except Exception as exc:  # pragma: no cover - depends on optional AGT deps
            self.agt_error = f"{type(exc).__name__}: {exc}"

    def map_event_to_articles(self, event: dict) -> list[str]:
        """Map one ASF/dashboard audit event to EU AI Act article labels."""
        articles = set(self._fallback_articles(event))
        articles.update(self._agt_articles(event))
        return sorted(articles, key=self._article_sort_key)

    def generate_compliance_report(self, events: list) -> dict:
        """Return a JSON-serializable compliance report for recent events."""
        normalized_events = [self._event_to_dict(event) for event in events]
        article_counts: Counter[str] = Counter()
        article_sources: dict[str, set[str]] = {}
        agt_controls_used: set[str] = set()
        event_mappings = []
        agt_mapping_hits = 0

        for index, event in enumerate(normalized_events):
            fallback_articles = self._fallback_articles(event)
            agt_article_controls = self._agt_article_controls(event)
            agt_articles = sorted(agt_article_controls, key=self._article_sort_key)
            if agt_articles:
                agt_mapping_hits += 1
                for controls in agt_article_controls.values():
                    agt_controls_used.update(controls)

            articles = sorted(set(fallback_articles) | set(agt_articles), key=self._article_sort_key)
            article_counts.update(articles)
            event_article_sources = self._article_sources(fallback_articles, agt_articles)
            for article, sources in event_article_sources.items():
                article_sources.setdefault(article, set()).update(sources)

            event_mappings.append({
                "event_index": index,
                "event_id": self._first_value(event, "event_id", "hash", "id"),
                "timestamp": self._first_value(event, "timestamp", "created_at"),
                "agent_id": self._first_value(event, "agent_id", "agent_did", "agent"),
                "action": self._first_value(event, "action", "event_type", "tool_name", "tool"),
                "outcome": self._first_value(event, "outcome", "verdict", "status"),
                "articles": articles,
                "agt_articles": sorted(set(agt_articles), key=self._article_sort_key),
                "fallback_articles": sorted(set(fallback_articles), key=self._article_sort_key),
                "article_sources": event_article_sources,
                "agt_controls": {
                    article: sorted(controls)
                    for article, controls in sorted(
                        agt_article_controls.items(),
                        key=lambda item: self._article_sort_key(item[0]),
                    )
                },
            })

        articles = [
            {
                "article": article,
                "control": ARTICLE_NAMES.get(article, "EU AI Act control"),
                "event_count": article_counts.get(article, 0),
                "status": "Active" if article_counts.get(article, 0) > 0 else "No evidence",
                "sources": sorted(article_sources.get(article, [])),
                "agt_verified": "agt" in article_sources.get(article, set()),
            }
            for article in sorted(ARTICLE_NAMES, key=self._article_sort_key)
        ]

        return {
            "framework": "eu_ai_act",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(normalized_events),
            "agt_verified": self.agt_verified,
            "source": "agt_compliance_engine_with_asf_mapping" if self.agt_verified else "asf_fallback_mapping",
            "article_counts": dict(sorted(article_counts.items(), key=lambda item: self._article_sort_key(item[0]))),
            "article_sources": {
                article: sorted(sources)
                for article, sources in sorted(article_sources.items(), key=lambda item: self._article_sort_key(item[0]))
            },
            "agt_controls": sorted(agt_controls_used),
            "articles": articles,
            "events": event_mappings,
            "metadata": {
                "agt_source_path": AGT_SRC_PATH,
                "agt_compliance_api": "ComplianceEngine" if self.agt_verified else None,
                "agt_error": self.agt_error,
                "agt_controls": sorted(self.agt_controls),
                "agt_controls_used": sorted(agt_controls_used),
                "agt_mappings": sorted(self.agt_mappings),
                "agt_mapping_hits": agt_mapping_hits,
                "fallback_mapping_applied": True,
                "event_limit": len(normalized_events),
            },
        }

    def _agt_articles(self, event: dict[str, Any]) -> list[str]:
        return sorted(self._agt_article_controls(event), key=self._article_sort_key)

    def _agt_article_controls(self, event: dict[str, Any]) -> dict[str, set[str]]:
        if not self.agt_verified or self.agt_engine is None:
            return {}

        action_types = self._candidate_agt_action_types(event)
        articles: dict[str, set[str]] = {}
        for action_type in action_types:
            try:
                mapping = self.agt_engine.map_action(action_type)
            except Exception:
                continue
            controls = getattr(mapping, "controls", []) if mapping is not None else []
            for control_id in controls:
                article = self._control_to_article(str(control_id))
                if article:
                    articles.setdefault(article, set()).add(str(control_id))
        return articles

    @staticmethod
    def _article_sources(fallback_articles: list[str], agt_articles: list[str]) -> dict[str, list[str]]:
        sources: dict[str, set[str]] = {}
        for article in fallback_articles:
            sources.setdefault(article, set()).add("asf_fallback")
        for article in agt_articles:
            sources.setdefault(article, set()).add("agt")
        return {article: sorted(labels) for article, labels in sources.items()}

    def _fallback_articles(self, event: dict[str, Any]) -> list[str]:
        text = self._event_text(event)
        articles = {"Art. 12", "Art. 13"}
        if self._contains_marker(text, BLOCKING_MARKERS):
            articles.add("Art. 9")
        if self._contains_marker(text, ALLOW_MARKERS):
            articles.add("Art. 15")
        if self._contains_marker(text, HITL_MARKERS):
            articles.add("Art. 14")
        return sorted(articles, key=self._article_sort_key)

    def _candidate_agt_action_types(self, event: dict[str, Any]) -> list[str]:
        text = self._event_text(event)
        candidates: list[str] = []
        for field in ("action_type", "action", "event_type", "tool_name", "tool"):
            value = self._first_value(event, field)
            if value:
                candidates.append(str(value))

        if self._contains_marker(text, BLOCKING_MARKERS):
            candidates.append("supply_chain_audit")
        if self._contains_marker(text, ALLOW_MARKERS | HITL_MARKERS):
            candidates.append("automated_decision")

        return list(dict.fromkeys(candidates))

    def _event_text(self, event: dict[str, Any]) -> str:
        values: list[str] = []
        for container in self._containers(event):
            for key in ("action", "outcome", "verdict", "status", "event_type", "tool_name", "tool", "action_type"):
                value = container.get(key)
                if value is not None:
                    values.append(str(value))
        return " ".join(values).upper()

    def _containers(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        containers = [event]
        for key in ("data", "metadata"):
            value = event.get(key)
            if isinstance(value, dict):
                containers.append(value)
                nested = value.get("metadata")
                if isinstance(nested, dict):
                    containers.append(nested)
        return containers

    def _first_value(self, event: dict[str, Any], *keys: str) -> Any:
        for container in self._containers(event):
            for key in keys:
                value = container.get(key)
                if value not in (None, ""):
                    return value
        return None

    def _event_to_dict(self, event: Any) -> dict[str, Any]:
        if isinstance(event, dict):
            return event
        if is_dataclass(event):
            return asdict(event)
        model_dump = getattr(event, "model_dump", None)
        if callable(model_dump):
            return model_dump()
        dict_method = getattr(event, "dict", None)
        if callable(dict_method):
            return dict_method()
        return {
            key: value
            for key, value in vars(event).items()
            if not key.startswith("_")
        }

    def _control_to_article(self, control_id: str) -> str | None:
        normalized = control_id.upper().replace("_", "-").replace(" ", "")
        if normalized.startswith("EUAI-ART"):
            return f"Art. {normalized.removeprefix('EUAI-ART')}"
        if normalized.startswith("EU-AI-ACT-ART"):
            return f"Art. {normalized.removeprefix('EU-AI-ACT-ART')}"
        return None

    def _contains_marker(self, text: str, markers: set[str]) -> bool:
        return any(marker in text for marker in markers)

    def _article_sort_key(self, article: str) -> int:
        try:
            return int(article.replace("Art.", "").strip())
        except ValueError:
            return 999


def agt_source_exists() -> bool:
    return Path(AGT_SRC_PATH).exists()
