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
        # "contacts.admin.email" -> "admin"
        # "registrar.name" -> "registrar"
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
        target = self.data
        for key in keys[:-1]:
            target = target.setdefault(key, {})

        last_key = keys[-1]
        val_str = str(value).strip()

        # Logique d'accumulation pour les listes ou les adresses multi-lignes
        if last_key in ["nameservers", "status"]:
            if last_key not in target: target[last_key] = []
            if val_str not in target[last_key]: target[last_key].append(val_str)
        elif not target.get(last_key):
            target[last_key] = val_str
        elif "contacts" in path or "registrar" in path:
            if val_str not in target[last_key]:
                target[last_key] = f"{target[last_key]}, {val_str}"


class SchemaMapper:
    """Responsable de la traduction des labels WHOIS en MappingTarget."""

    def __init__(self, mapping: Dict[str, List[str]]):
        self.mapping = mapping
        # Sections définies dans les constantes (ex: "SECTION_ADMIN" devient "administrative")
        self.sections = {
            "SECTION_ADMIN": "administrative",
            "SECTION_TECH": "technical",
            "SECTION_REGISTRANT": "registrant",
            "SECTION_BILLING": "billing",
            "SECTION_REGISTRAR": "registrar"  # On peut l'ajouter s'il existe
        }
        self.flat_choices = [alias for aliases in mapping.values() for alias in aliases]

    def resolve(self, label: str, current_section: Optional[str]) -> Optional[MappingTarget]:
        clean = label.lower().replace(":", "").strip()
        if not clean: return None

        # 1. Vérifier si c'est un changement de section
        for key, aliases in self.mapping.items():
            if key.startswith("SECTION_"):
                if clean in [a.lower() for a in aliases]:
                    # Traduction du nom de la section (ex: SECTION_ADMIN -> administrative)
                    sect_name = self.sections.get(key, key.replace("SECTION_", "").lower())
                    path = f"contacts.{sect_name}" if sect_name != "registrar" else "registrar"
                    return MappingTarget(path=path, is_section=True)

        # 2. Match avec contexte de section (Registrar inclus !)
        if current_section:
            prefix = "registrar" if current_section == "registrar" else f"contacts.{current_section}"
            choices = [k for k in self.mapping.keys() if k.startswith(prefix)]
            for key in choices:
                if clean in [a.lower() for a in self.mapping[key]]:
                    return MappingTarget(path=key)

        # 3. Match Global
        match = process.extractOne(clean, self.flat_choices, scorer=fuzz.token_sort_ratio)
        if match and match[1] > 85:
            for key, aliases in self.mapping.items():
                if match[0] in aliases and not key.startswith("SECTION_"):
                    # Sécurité section
                    if ("contacts." in key or "registrar." in key) and current_section:
                        if not key.startswith(f"contacts.{current_section}") and not key.startswith("registrar."):
                            if match[1] < 95: continue
                    return MappingTarget(path=key)
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

            target = self.mapper.resolve(label, self.ctx.current_section)

            if target:
                if target.is_section:
                    self.ctx.current_section = target.section_name
                    if value:
                        # Si la section a une valeur directe (ex: "Registrant: John Doe")
                        # On l'assigne au champ 'name' de cette section
                        self.ctx.update_value(f"{target.path}.name", value)
                    self.walk(children)
                else:
                    if value: self.ctx.update_value(target.path, value)
                    for child in children:
                        if isinstance(child, str):
                            self.ctx.update_value(target.path, child)
                        else:
                            self.walk([child])
            else:
                # Cas Inconnu
                if value:
                    key = f"{self.ctx.current_section}.{label}" if self.ctx.current_section else label
                    self.ctx.data["other"][key] = value
                self.walk(children)


def normalize_whois_tree_fuzzy(tree_list: List[Any]) -> Dict[str, Any]:
    engine = WhoisEngine()
    engine.walk(tree_list)
    # Nettoyage final des clés vides
    return {k: v for k, v in engine.ctx.data.items() if v}