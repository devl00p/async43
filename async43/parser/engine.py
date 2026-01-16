from dataclasses import dataclass
from typing import List, Optional, Any, Dict, Union
from rapidfuzz import process, fuzz
from async43.parser.constants import SCHEMA_MAPPING


@dataclass
class MappingTarget:
    """Représente une destination dans le dictionnaire final."""
    path: str
    is_section: bool = False

    @property
    def section_name(self) -> str:
        parts = self.path.split('.')
        return parts[1] if parts[0] == "contacts" else parts[0]


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
        # Le format .sk a des dates de création/update pour CHAQUE contact.
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

    def resolve(self, label: str, current_section: Optional[str]) -> Optional[MappingTarget]:
        clean = label.lower().replace(":", "").strip()
        if not clean: return None

        # 1. Détection de changement de section (Labels spéciaux comme "Administrative Contact")
        for key, aliases in self.mapping.items():
            if key.startswith("SECTION_"):
                if clean in [a.lower() for a in aliases]:
                    # Traduit "SECTION_REGISTRANT" -> "registrant"
                    sect_name = key.replace("SECTION_", "").lower()
                    path = f"contacts.{sect_name}" if sect_name != "registrar" else "registrar"
                    return MappingTarget(path=path, is_section=True)

        # Spécial pour .sk : "Registrar" ou "Domain registrant" sont des déclencheurs
        if clean == "registrar" or clean == "authorised registrar":
            return MappingTarget(path="registrar", is_section=True)
        if clean == "domain registrant":
            return MappingTarget(path="contacts.registrant", is_section=True)

        # 2. Construction du label virtuel avec préfixe (ton idée)
        search_terms = []
        if current_section:
            search_terms.append(f"{current_section} {clean}")  # ex: "registrar name"
        search_terms.append(clean)  # ex: "name"

        for term in search_terms:
            # Match Exact d'abord
            for path, aliases in self.mapping.items():
                if term in [a.lower() for a in aliases]:
                    return MappingTarget(path=path)

            # Fuzzy Match ensuite
            match = process.extractOne(term, self.flat_choices, scorer=fuzz.token_sort_ratio)
            if match and match[1] > 90:  # Seuil haut pour éviter les faux positifs
                for path, aliases in self.mapping.items():
                    if match[0] in aliases and not key.startswith("SECTION_"):
                        return MappingTarget(path=path)

        return None


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

            target = self.mapper.resolve(label, self.ctx.current_section)

            if target:
                if target.is_section:
                    # On définit la section courante (ex: "registrar")
                    self.ctx.current_section = target.section_name

                    # Si la ligne de section a une valeur (ex: Registrar: INCZ-0001)
                    if value:
                        # On cherche une clé .id ou .handle ou .name pour cette section
                        field = "name" if self.ctx.current_section == "registrar" else "handle"
                        self.ctx.update_value(f"{target.path}.{field}", value)
                else:
                    # On est dans un champ de données classique
                    self.ctx.update_value(target.path, value)

                # On traite les enfants (si structure hiérarchique)
                self.walk(children)
            else:
                # Cas Inconnu : On garde le contexte pour classer l'info
                if value:
                    prefix = self.ctx.current_section if self.ctx.current_section else "global"
                    self.ctx.data["other"][f"{prefix}.{label}"] = value
                self.walk(children)


def normalize_whois_tree_fuzzy(tree_list: List[Any]) -> Dict[str, Any]:
    engine = WhoisEngine()
    engine.walk(tree_list)
    # Nettoyage final des clés vides
    return {k: v for k, v in engine.ctx.data.items() if v}