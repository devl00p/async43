from dataclasses import dataclass
from typing import List, Optional, Any, Dict
from rapidfuzz import process, fuzz
from async43.parser.constants import SCHEMA_MAPPING


@dataclass
class MappingTarget:
    """Représente une destination dans le dictionnaire final."""
    path: str

    @property
    def section_name(self) -> Optional[str]:
        """Extrait le nom de section si applicable (contacts.X ou registrar)."""
        parts = self.path.split('.')
        if parts[0] == "contacts" and len(parts) > 1:
            return parts[1]
        elif parts[0] == "registrar":
            return "registrar"
        return None


@dataclass
class SectionTrigger:
    """Indique qu'on entre dans une nouvelle section."""
    section_name: str  # Ex: "registrant", "administrative", "registrar"


@dataclass
class ResolveResult:
    """Résultat du resolve : peut contenir un trigger de section ET/OU un mapping."""
    section_trigger: Optional[SectionTrigger] = None
    mapping: Optional[MappingTarget] = None


class WhoisContext:
    """Gère l'état de la progression dans l'arbre WHOIS."""

    def __init__(self):
        self.current_section: Optional[str] = None
        self.data: Dict[str, Any] = self._init_structure()

    def _init_structure(self) -> Dict[str, Any]:
        return {
            "dates": {}, "registrar": {}, "nameservers": [], "status": [],
            "contacts": {k: {} for k in ["registrant", "administrative", "technical", "abuse", "billing"]},
            "other": {}
        }

    def update_value(self, path: str, value: Any):
        if not value or str(value).strip().lower() in ["none", "no name servers provided"]:
            return

        keys = path.split('.')

        # --- PROTECTION DES DATES ---
        # Si on est dans une section (admin/tech/etc), on n'écrit pas dans 'dates' global.
        if keys[0] == "dates" and self.current_section:
            return

        target = self.data
        for key in keys[:-1]:
            target = target.setdefault(key, {})

        last_key = keys[-1]
        val_str = str(value).strip()

        if last_key in ["nameservers", "status"]:
            if last_key not in target: target[last_key] = []
            if val_str not in target[last_key]: target[last_key].append(val_str)
        elif not target.get(last_key):
            target[last_key] = val_str
        elif "contacts" in path or "registrar" in path:
            # Accumulation pour les adresses multi-lignes
            if val_str not in target[last_key]:
                target[last_key] = f"{target[last_key]}, {val_str}"


class SchemaMapper:
    def __init__(self, mapping: Dict[str, List[str]]):
        self.mapping = mapping
        self.flat_choices = [alias for aliases in mapping.values() for alias in aliases]

        # Préparer les déclencheurs de section
        self.section_triggers = {}
        for key, aliases in mapping.items():
            if key.startswith("SECTION_"):
                sect_name = key.replace("SECTION_", "").lower()
                for alias in aliases:
                    self.section_triggers[alias.lower()] = sect_name

        # Ajouter les valeurs qui peuvent indiquer des sections
        # (utilisées quand label="contact" value="administrative")
        self.section_value_triggers = {
            "administrative": "administrative",
            "technical": "technical",
            "registrant": "registrant",
            "billing": "billing",
            "abuse": "abuse",
        }

    def detect_section_from_value(self, label: str, value: Optional[str]) -> Optional[str]:
        """
        Détecte si une valeur indique un changement de section.
        Ex: label="contact", value="administrative" → section "administrative"
        """
        if not value:
            return None

        label_clean = label.lower().strip()
        value_clean = value.lower().strip()

        # Cas type IANA : "contact: administrative"
        if label_clean in ["contact", "contacts"]:
            if value_clean in self.section_value_triggers:
                return self.section_value_triggers[value_clean]

        # Cas alternatif : "registry registrantid" où la valeur pourrait être un ID
        # mais le label contient déjà l'indication de section
        # (géré par detect_section_from_label)

        return None

    def detect_section_from_label(self, label: str) -> Optional[str]:
        """
        Détecte si un label indique un changement de section.
        Ex: "Registrar", "Domain registrant", "Registry AdminID"
        """
        clean = label.lower().replace(":", "").strip()

        # Sections explicites du mapping (SECTION_XXX)
        if clean in self.section_triggers:
            return self.section_triggers[clean]

        # Cas spéciaux
        if clean == "registrar" or clean == "authorised registrar":
            return "registrar"
        if clean == "domain registrant":
            return "registrant"

        # Détection par préfixe dans le label (ex: "Registry AdminID", "AdminName")
        # On cherche si le label contient un mot-clé de section
        for section_keyword in ["registrant", "admin", "tech", "billing"]:
            if section_keyword in clean:
                # Mapper "admin" → "administrative", etc.
                section_map = {
                    "admin": "administrative",
                    "tech": "technical",
                    "registrant": "registrant",
                    "billing": "billing"
                }
                return section_map.get(section_keyword, section_keyword)

        return None

    def resolve(self, label: str, value: Optional[str], current_section: Optional[str]) -> ResolveResult:
        """
        Résout un label/valeur en déterminant :
        1. Si c'est un déclencheur de section (label OU valeur)
        2. Si c'est un champ de données (avec contexte de section)
        """
        clean = label.lower().replace(":", "").strip()
        if not clean:
            return ResolveResult()

        result = ResolveResult()

        # --- ÉTAPE 1 : Détecter les déclencheurs de section ---

        # A. D'abord vérifier si la VALEUR indique une section (ex: "contact: administrative")
        section_from_value = self.detect_section_from_value(label, value)
        if section_from_value:
            result.section_trigger = SectionTrigger(section_name=section_from_value)
            print(f"→ Section détectée depuis valeur: {label}={value} → {section_from_value}")
            # Dans ce cas, on ne mappe PAS la valeur comme donnée
            # car "administrative" n'est pas une valeur à stocker
            return result

        # B. Sinon vérifier si le LABEL indique une section
        section_from_label = self.detect_section_from_label(label)
        if section_from_label:
            result.section_trigger = SectionTrigger(section_name=section_from_label)
            print(f"→ Section détectée depuis label: {label} → {section_from_label}")

            # Cas spécial : si le label EST le nom de la section (ex: "Registrar:", "Domain registrant:")
            # et qu'il y a une valeur, on mappe automatiquement vers section.name
            if clean in ["registrar", "domain registrant", "authorised registrar"] and value:
                # Construire le path approprié
                if section_from_label == "registrar":
                    result.mapping = MappingTarget(path="registrar.name")
                else:
                    result.mapping = MappingTarget(path=f"contacts.{section_from_label}.name")
                print(f"→ Mapping automatique de section trigger avec valeur: {result.mapping.path}")
                return result

            # Sinon on continue pour tenter de mapper la donnée normalement

        # --- ÉTAPE 2 : Tenter de mapper vers un champ de données ---

        # Construction du label avec contexte
        # Si on vient de détecter une section, on l'utilise comme contexte immédiat
        effective_section = section_from_label if section_from_label else current_section

        search_terms = []

        if effective_section and clean.startswith(effective_section):
            suffix = clean[len(effective_section):].strip()
            if suffix:  # S'il reste quelque chose après le préfixe
                # Ajouter "registrant city" (séparé correctement)
                search_terms.append(f"{effective_section} {suffix}")

        if effective_section:
            search_terms.append(f"{effective_section} {clean}")
        search_terms.append(clean)

        # D'ABORD : tester tous les termes en exact match
        for term in search_terms:
            for path, aliases in self.mapping.items():
                if path.startswith("SECTION_"):
                    continue  # Ignorer les marqueurs de section

                if term in [a.lower() for a in aliases]:
                    print(f"exact: '{term}' -> '{path}'")
                    result.mapping = MappingTarget(path=path)
                    return result

        # ENSUITE : si aucun exact match, tester en fuzzy
        for term in search_terms:
            match = process.extractOne(term, self.flat_choices, scorer=fuzz.token_sort_ratio)
            if match and match[1] > 90:
                for path, aliases in self.mapping.items():
                    if path.startswith("SECTION_"):
                        continue

                    if match[0] in aliases:
                        print(f"fuzzy: '{term}' -> '{match[0]}' -> '{path}'")
                        result.mapping = MappingTarget(path=path)
                        return result

        if not result.section_trigger and not result.mapping:
            print(f"{clean} -> None")

        return result


class WhoisEngine:
    """Le cerveau qui parcourt l'arbre et utilise le Mapper et le Context."""

    def __init__(self):
        self.mapper = SchemaMapper(SCHEMA_MAPPING)
        self.ctx = WhoisContext()

    def walk(self, nodes: List[Any]):
        for node in nodes:
            label = getattr(node, 'label', "").strip()
            value = getattr(node, 'value', None)
            children = getattr(node, 'children', [])

            if label == "SECTION_BREAK":
                self.ctx.current_section = None
                continue

            result = self.mapper.resolve(label, value, self.ctx.current_section)

            # --- Traiter le déclencheur de section (si présent) ---
            if result.section_trigger:
                self.ctx.current_section = result.section_trigger.section_name
                print(f"→ Entrée dans section: {self.ctx.current_section}")

            # --- Traiter le mapping de données (si présent) ---
            if result.mapping:
                # Déterminer si c'est un champ global (qui force la sortie de section)
                is_global = not any(
                    result.mapping.path.startswith(p)
                    for p in ["contacts", "registrar"]
                )

                if is_global:
                    # Les champs globaux (dates, nameservers, status, dnssec)
                    # nous font sortir de toute section
                    self.ctx.current_section = None

                # Enregistrer la valeur
                if value:
                    self.ctx.update_value(result.mapping.path, value)

            # --- Cas spécial : aucun résultat mais on a une valeur ---
            elif not result.section_trigger and value:
                # Stocker dans "other" avec préfixe de contexte
                prefix = self.ctx.current_section if self.ctx.current_section else "global"
                self.ctx.data["other"][f"{prefix}.{label}"] = value

            # --- Traiter les enfants récursivement ---
            self.walk(children)


def normalize_whois_tree_fuzzy(tree_list: List[Any]) -> Dict[str, Any]:
    engine = WhoisEngine()
    engine.walk(tree_list)
    # Nettoyage final des clés vides
    return {k: v for k, v in engine.ctx.data.items() if v}