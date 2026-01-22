import logging
from dataclasses import dataclass
from typing import List, Optional, Any, Dict

from rapidfuzz import process, fuzz
from text_scrubber.geo import find_city_in_string, find_country_in_string

from async43.parser.constants import SCHEMA_MAPPING
from async43.parser.detector import HeuristicDetector
from async43.parser.structure import Node

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
    """
    Holds the mutable parsing state and accumulates normalized WHOIS data.

    This class acts as a write-context during the WHOIS tree traversal:
    - tracks the currently active logical section (registrant, admin, registrar, etc.)
    - stores extracted values in a structured, normalized dictionary
    - applies contextual rules (e.g. section-aware date handling, value accumulation)
    """

    def __init__(self):
        """
        Initialize a new parsing context.

        The context starts with no active section and an empty,
        pre-initialized data structure ready to receive parsed values.
        """
        self.current_section: Optional[str] = None
        self.data: Dict[str, Any] = self._init_structure()

    def _init_structure(self) -> Dict[str, Any]:
        """
        Initialize the base structure used to store normalized WHOIS data.

        This structure matches the expected shape of the final Whois model
        and ensures all known sections are present even if empty.

        :return: A dictionary representing the initial WHOIS data layout.
        """
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
        """
        Store a parsed value into the normalized data structure.

        The target location is defined by a dotted path (e.g.
        ``contacts.administrative.email`` or ``dates.created``).

        This method applies several normalization rules:
        - ignores empty or placeholder values
        - prevents section-scoped dates from overwriting global dates
        - accumulates list-based fields such as nameservers and status
        - concatenates multi-line contact and registrar fields

        :param path: Dotted path indicating where the value should be stored.
        :param value: Raw value extracted from the WHOIS response.
        """
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
        # Revert mapping so we have a "technical contact" to "technical" section logic
        for key, aliases in mapping.items():
            if key.startswith("SECTION_"):
                section = key.replace("SECTION_", "").lower()
                for alias in aliases:
                    self.section_triggers[alias.lower()] = section

        # Allows to detect sections from values like "contact: technical".
        # Values here can look stupid but may evolve
        self.section_value_triggers = {
            "administrative": "administrative",
            "technical": "technical",
            "registrant": "registrant",
            "registrar": "registrar",
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

        return None

    def _try_auto_map_section_header(
            self,
            clean_label: str,
            section_name: str,
            value: Optional[str],
    ) -> Optional[MappingTarget]:
        """
        Auto-map section header labels with values to the .name field.

        Example: "Registrar: MarkMonitor Inc." -> registrar.name
        """
        if clean_label not in {"registrar", "domain registrant", "authorised registrar"}:
            return None

        if not value:
            return None

        path = (
            "registrar.name"
            if section_name == "registrar"
            else f"contacts.{section_name}.name"
        )
        logger.debug("Auto-mapping section header with value to %s", path)
        return MappingTarget(path)

    def _build_search_terms(
            self,
            clean_label: str,
            effective_section: Optional[str],
    ) -> List[str]:
        """
        Build search terms for label matching with context.

        Handles cases like "RegistrantCity" by separating prefix from suffix.
        """
        search_terms: List[str] = []

        if effective_section and clean_label.startswith(effective_section):
            suffix = clean_label[len(effective_section):].strip()
            if suffix:
                search_terms.append(f"{effective_section} {suffix}")

        if effective_section:
            search_terms.append(f"{effective_section} {clean_label}")

        search_terms.append(clean_label)
        return search_terms

    def _try_exact_match(self, term: str) -> Optional[MappingTarget]:
        """
        Attempt exact match of term against mapping aliases.

        Returns the first matching path, or None if no match found.
        """
        for path, aliases in self.mapping.items():
            if path.startswith("SECTION_"):
                continue
            if term in (a.lower() for a in aliases):
                logger.debug("Exact match: '%s' -> %s", term, path)
                return MappingTarget(path)
        return None

    def _try_fuzzy_match(self, term: str) -> Optional[MappingTarget]:
        """
        Attempt fuzzy match of term against mapping aliases.

        Uses rapidfuzz with token_sort_ratio and 90% threshold.
        Returns the first matching path, or None if no match found.
        """
        match = process.extractOne(
            term, self.flat_choices, scorer=fuzz.token_sort_ratio
        )
        if not match or match[1] <= 90:
            return None

        for path, aliases in self.mapping.items():
            if path.startswith("SECTION_"):
                continue
            if match[0] in aliases:
                logger.debug(
                    "Fuzzy match: '%s' -> '%s' -> %s",
                    term, match[0], path,
                )
                return MappingTarget(path)
        return None

    def _try_map_to_field(self, search_terms: List[str]) -> Optional[MappingTarget]:
        """
        Try to map search terms to a field path.

        Attempts exact matches first, then fuzzy matches.
        """
        for term in search_terms:
            mapping = self._try_exact_match(term)
            if mapping:
                return mapping

        for term in search_terms:
            mapping = self._try_fuzzy_match(term)
            if mapping:
                return mapping

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

            auto_mapping = self._try_auto_map_section_header(
                clean, section_from_label, value
            )
            if auto_mapping:
                result.mapping = auto_mapping
                return result

        effective_section = section_from_label or current_section
        search_terms = self._build_search_terms(clean, effective_section)

        mapping = self._try_map_to_field(search_terms)
        if mapping:
            result.mapping = mapping
        else:
            logger.debug("Unresolved label: %s", clean)

        return result


class WhoisEngine:
    """
    Traverses the parsed WHOIS tree and builds a normalized WHOIS output.

    This engine performs a depth-first traversal of a parsed WHOIS tree,
    resolving nodes using a schema mapper and enriching the output using
    heuristic detectors (email, phone, location).

    The traversal maintains contextual state (current section) and writes
    results directly into a ``WhoisContext`` instance.
    """

    def __init__(self):
        self.mapper = SchemaMapper(SCHEMA_MAPPING)
        self.ctx = WhoisContext()
        self.detector = HeuristicDetector()

    def walk(self, nodes: List[Any]) -> None:
        """
        Walk a parsed WHOIS tree and populate the normalized WHOIS context.

        This method orchestrates the traversal by delegating the processing
        of structured nodes and raw text lines to specialized handlers.
        """
        raw_lines = [n for n in nodes if isinstance(n, str)]
        detected_countries = (
            self.detector.get_countries(raw_lines) if raw_lines else set()
        )

        for node in nodes:
            if isinstance(node, Node):
                self._handle_node(node)
            else:
                self._handle_text_line(node, detected_countries)

    def _handle_node(self, node: Node) -> None:
        """
        Handle a structured parse tree node.

        This resolves schema mappings, manages section transitions,
        stores mapped or unmapped values, and recursively walks child nodes.
        """
        label = node.label.strip()

        if label == "SECTION_BREAK":
            self.ctx.current_section = None
            return

        result = self.mapper.resolve(
            label, node.value, self.ctx.current_section
        )

        self._handle_section_trigger(result)
        self._handle_mapping(result, label, node.value)

        self.walk(node.children)

    def _handle_section_trigger(self, result) -> None:
        """
        Update the current section if the mapper indicates a section trigger.
        """
        if not result.section_trigger:
            return

        self.ctx.current_section = result.section_trigger.section_name
        logger.debug("Entering section: %s", self.ctx.current_section)

    def _handle_mapping(self, result, label: str, value: Any) -> None:
        """
        Apply a schema mapping or store an unmapped value.
        """
        if not value:
            return

        if result.mapping:
            if result.mapping.path.endswith(".email"):
                value = self.detector.detect_email(value) or self.detector.detect_email(value.replace("AT", "@"))

            self._apply_mapping(result.mapping.path, value)
            return

        if not result.section_trigger:
            self._store_unmapped_value(label, value)

    def _apply_mapping(self, path: str, value: Any) -> None:
        """
        Apply a resolved schema mapping to the context.
        """
        if not value:
            return

        if self._is_global_mapping(path):
            self.ctx.current_section = None

        self.ctx.update_value(path, value)

    @staticmethod
    def _is_global_mapping(path: str) -> bool:
        """
        Determine whether a mapping path belongs to the global scope.
        """
        return not path.startswith(("contacts", "registrar"))

    def _store_unmapped_value(self, label: str, value: Any) -> None:
        """
        Store a value that could not be resolved by the schema mapper.
        """
        prefix = self.ctx.current_section or "global"
        self.ctx.data["other"][f"{prefix}.{label}"] = value

    def _handle_text_line(
        self, node: str, detected_countries: set
    ) -> None:
        """
        Handle a raw text line within the current section.

        This method attempts to detect and store email addresses,
        phone numbers, and location information.
        """
        content = node.strip()

        if not content or not self.ctx.current_section:
            return

        if self._handle_email(content):
            return

        if self._handle_phone(content):
            return

        self._handle_location(content, detected_countries)

    def _handle_email(self, content: str) -> bool:
        """
        Detect and store an email address from a text line.
        """
        if "@" not in content:
            return False

        email = self.detector.detect_email(content)
        if not email:
            return False

        self.ctx.update_value(self._contact_path("email"), email)
        return True

    def _handle_phone(self, content: str) -> bool:
        """
        Detect and store a phone number from a text line.
        """
        if not self.detector.detect_phone(content):
            return False

        self.ctx.update_value(self._contact_path("phone"), content)
        return True

    def _handle_location(
        self, content: str, detected_countries: set
    ) -> None:
        """
        Detect and store city and country information from a text line.
        """
        if detected_countries:
            cities = find_city_in_string(
                content, country_set=detected_countries
            )
            if cities:
                self.ctx.update_value(
                    self._contact_path("city"),
                    cities[0].location.canonical_name,
                )

        country_match = find_country_in_string(content)
        if country_match:
            self.ctx.update_value(
                self._contact_path("country"),
                country_match[0].location.canonical_name,
            )

    def _contact_path(self, field: str) -> str:
        """
        Build a contact-related storage path based on the current section.
        """
        if self.ctx.current_section == "registrar":
            return f"registrar.{field}"

        return f"contacts.{self.ctx.current_section}.{field}"



def normalize_whois_tree_fuzzy(
    tree_list: List[Any],
) -> Dict[str, Any]:
    """Normalize a parsed WHOIS tree using fuzzy schema matching."""
    engine = WhoisEngine()
    engine.walk(tree_list)
    return {k: v for k, v in engine.ctx.data.items() if v}
