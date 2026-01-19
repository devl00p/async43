import logging
from dataclasses import dataclass
from typing import List, Optional, Any, Dict

from rapidfuzz import process, fuzz

from async43.parser.constants import SCHEMA_MAPPING

logger = logging.getLogger("async43")


@dataclass
class MappingTarget:
    """Represents a destination path in the final normalized dictionary."""
    path: str

    @property
    def section_name(self) -> Optional[str]:
        """Extract the section name from the mapping path, if applicable."""
        parts = self.path.split(".")
        if parts[0] == "contacts" and len(parts) > 1:
            return parts[1]
        if parts[0] == "registrar":
            return "registrar"
        return None


@dataclass
class SectionTrigger:
    """Indicates that a new WHOIS section has been entered."""
    section_name: str


@dataclass
class ResolveResult:
    """Result of label/value resolution."""
    section_trigger: Optional[SectionTrigger] = None
    mapping: Optional[MappingTarget] = None


class WhoisContext:
    """Maintains parsing state and accumulates normalized WHOIS data."""

    def __init__(self):
        self.current_section: Optional[str] = None
        self.data: Dict[str, Any] = self._init_structure()

    def _init_structure(self) -> Dict[str, Any]:
        return {
            "dates": {},
            "registrar": {},
            "nameservers": [],
            "status": [],
            "contacts": {
                k: {} for k in
                ["registrant", "administrative", "technical", "abuse", "billing"]
            },
            "other": {},
        }

    def update_value(self, path: str, value: Any) -> None:
        if not value or str(value).strip().lower() in {
            "none", "no name servers provided"
        }:
            return

        keys = path.split(".")

        if keys[0] == "dates" and self.current_section:
            return

        target = self.data
        for key in keys[:-1]:
            target = target.setdefault(key, {})

        last_key = keys[-1]
        val_str = str(value).strip()

        if last_key in {"nameservers", "status"}:
            target.setdefault(last_key, [])
            if val_str not in target[last_key]:
                target[last_key].append(val_str)
            return

        if not target.get(last_key):
            target[last_key] = val_str
            return

        if "contacts" in path or "registrar" in path:
            if val_str not in target[last_key]:
                target[last_key] = f"{target[last_key]}, {val_str}"


class SchemaMapper:
    """Maps WHOIS labels and values to normalized schema paths."""

    def __init__(self, mapping: Dict[str, List[str]]):
        self.mapping = mapping
        self.flat_choices = [
            alias for aliases in mapping.values() for alias in aliases
        ]

        self.section_triggers: Dict[str, str] = {}
        for key, aliases in mapping.items():
            if key.startswith("SECTION_"):
                section = key.replace("SECTION_", "").lower()
                for alias in aliases:
                    self.section_triggers[alias.lower()] = section

        self.section_value_triggers = {
            "administrative": "administrative",
            "technical": "technical",
            "registrant": "registrant",
            "billing": "billing",
            "abuse": "abuse",
        }

    def detect_section_from_value(
        self, label: str, value: Optional[str]
    ) -> Optional[str]:
        """Detect section transitions from the field value."""
        if not value:
            return None

        label_clean = label.lower().strip()
        value_clean = value.lower().strip()

        if label_clean in {"contact", "contacts"}:
            return self.section_value_triggers.get(value_clean)

        return None

    def detect_section_from_label(self, label: str) -> Optional[str]:
        """Detect section transitions from the field label."""
        clean = label.lower().replace(":", "").strip()

        if clean in self.section_triggers:
            return self.section_triggers[clean]

        if clean in {"registrar", "authorised registrar"}:
            return "registrar"
        if clean == "domain registrant":
            return "registrant"

        for keyword, mapped in {
            "admin": "administrative",
            "tech": "technical",
            "registrant": "registrant",
            "billing": "billing",
        }.items():
            if keyword in clean:
                return mapped

        return None

    def resolve(
        self,
        label: str,
        value: Optional[str],
        current_section: Optional[str],
    ) -> ResolveResult:
        """Resolve a label/value pair into a section trigger and/or a mapping."""
        clean = label.lower().replace(":", "").strip()
        if not clean:
            return ResolveResult()

        result = ResolveResult()

        section_from_value = self.detect_section_from_value(label, value)
        if section_from_value:
            logger.debug(
                "Section detected from value: %s=%s -> %s",
                label, value, section_from_value,
            )
            result.section_trigger = SectionTrigger(section_from_value)
            return result

        section_from_label = self.detect_section_from_label(label)
        if section_from_label:
            logger.debug(
                "Section detected from label: %s -> %s",
                label, section_from_label,
            )
            result.section_trigger = SectionTrigger(section_from_label)

            if clean in {
                "registrar",
                "domain registrant",
                "authorised registrar",
            } and value:
                path = (
                    "registrar.name"
                    if section_from_label == "registrar"
                    else f"contacts.{section_from_label}.name"
                )
                logger.debug(
                    "Auto-mapping section header with value to %s", path
                )
                result.mapping = MappingTarget(path)
                return result

        effective_section = section_from_label or current_section
        search_terms: List[str] = []

        if effective_section and clean.startswith(effective_section):
            suffix = clean[len(effective_section):].strip()
            if suffix:
                search_terms.append(f"{effective_section} {suffix}")

        if effective_section:
            search_terms.append(f"{effective_section} {clean}")
        search_terms.append(clean)

        for term in search_terms:
            for path, aliases in self.mapping.items():
                if path.startswith("SECTION_"):
                    continue
                if term in (a.lower() for a in aliases):
                    logger.debug("Exact match: '%s' -> %s", term, path)
                    result.mapping = MappingTarget(path)
                    return result

        for term in search_terms:
            match = process.extractOne(
                term, self.flat_choices, scorer=fuzz.token_sort_ratio
            )
            if match and match[1] > 90:
                for path, aliases in self.mapping.items():
                    if path.startswith("SECTION_"):
                        continue
                    if match[0] in aliases:
                        logger.debug(
                            "Fuzzy match: '%s' -> '%s' -> %s",
                            term, match[0], path,
                        )
                        result.mapping = MappingTarget(path)
                        return result

        logger.debug("Unresolved label: %s", clean)
        return result


class WhoisEngine:
    """Traverses the parsed WHOIS tree and builds normalized output."""

    def __init__(self):
        self.mapper = SchemaMapper(SCHEMA_MAPPING)
        self.ctx = WhoisContext()

    def walk(self, nodes: List[Any]) -> None:
        for node in nodes:
            label = getattr(node, "label", "").strip()
            value = getattr(node, "value", None)
            children = getattr(node, "children", [])

            if label == "SECTION_BREAK":
                self.ctx.current_section = None
                continue

            result = self.mapper.resolve(
                label, value, self.ctx.current_section
            )

            if result.section_trigger:
                self.ctx.current_section = result.section_trigger.section_name
                logger.debug(
                    "Entering section: %s", self.ctx.current_section
                )

            if result.mapping:
                is_global = not result.mapping.path.startswith(
                    ("contacts", "registrar")
                )
                if is_global:
                    self.ctx.current_section = None

                if value:
                    self.ctx.update_value(result.mapping.path, value)

            elif not result.section_trigger and value:
                prefix = self.ctx.current_section or "global"
                self.ctx.data["other"][f"{prefix}.{label}"] = value

            self.walk(children)


def normalize_whois_tree_fuzzy(
    tree_list: List[Any],
) -> Dict[str, Any]:
    """Normalize a parsed WHOIS tree using fuzzy schema matching."""
    engine = WhoisEngine()
    engine.walk(tree_list)
    return {k: v for k, v in engine.ctx.data.items() if v}
