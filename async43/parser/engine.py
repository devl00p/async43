from typing import List, Optional, Any, Dict
from rapidfuzz import process, fuzz
from async43.parser.constants import SCHEMA_MAPPING


class WhoisTreeProcessor:
    def __init__(self):
        self.result = self._is_empty_template()
        self.current_section: Optional[str] = None

        # Pré-calculer les choix pour le fuzzy matching global
        self.flat_choices = []
        for aliases in SCHEMA_MAPPING.values():
            self.flat_choices.extend(aliases)

    def _is_empty_template(self) -> Dict[str, Any]:
        """Initialise la structure de base du dictionnaire de sortie."""
        return {
            "dates": {},
            "registrar": {},
            "nameservers": [],
            "status": [],
            "contacts": {
                "registrant": {},
                "administrative": {},
                "technical": {},
                "abuse": {},
                "billing": {},
            },
            "other": {}
        }

    def _map_label_to_path(self, raw_label: str) -> Optional[str]:
        """Transforme un label texte en chemin dans le schéma (ex: contacts.registrant.email)."""
        if not raw_label:
            return None

        clean = raw_label.lower().replace(":", "").strip()

        # 1. Détection de changement de section (Priorité haute)
        for key, aliases in SCHEMA_MAPPING.items():
            if key.startswith("SECTION_") and clean in [a.lower() for a in aliases]:
                return key

        # 2. Match avec contexte (Section actuelle)
        if self.current_section:
            context_keys = [k for k in SCHEMA_MAPPING.keys() if k.startswith(f"contacts.{self.current_section}")]
            for key in context_keys:
                aliases = SCHEMA_MAPPING[key]
                if clean in [a.lower() for a in aliases]:
                    return key
                # Fuzzy match restrictif
                res = process.extractOne(clean, aliases, scorer=fuzz.token_sort_ratio)
                if res and res[1] > 90:
                    return key

        # 3. Match Global
        match = process.extractOne(clean, self.flat_choices, scorer=fuzz.token_sort_ratio)
        if match and match[1] > 85:
            for key, aliases in SCHEMA_MAPPING.items():
                if match[0] in aliases:
                    # Sécurité : éviter de sauter dans une autre section contact par erreur
                    if "contacts." in key and self.current_section:
                        if not key.startswith(f"contacts.{self.current_section}") and match[1] < 95:
                            continue
                    return key
        return None

    def _set_value(self, path: str, value: Any):
        """Injecte une valeur dans le dictionnaire final en suivant le chemin 'pointé'."""
        if not value or str(value).strip().lower() in ["no name servers provided", "none"]:
            return

        keys = path.split('.')
        target = self.result

        # Navigation dans le dictionnaire
        for key in keys[:-1]:
            target = target.setdefault(key, {})

        target_key = keys[-1]
        value = str(value).strip()

        # Logique spécifique par type de champ
        if target_key in ["nameservers", "status"]:
            if target_key not in target:
                target[target_key] = []
            if value not in target[target_key]:
                target[target_key].append(value)
        elif not target.get(target_key):
            target[target_key] = value
        else:
            # Accumulation pour les champs de contact (ex: adresses multi-lignes)
            if "contacts" in path and value not in target[target_key]:
                target[target_key] = f"{target[target_key]}, {value}"

    def process(self, nodes: List[Any]) -> Dict[str, Any]:
        """Point d'entrée principal pour traiter une liste de nodes."""
        for node in nodes:
            label = getattr(node, 'label', "").strip()
            value = getattr(node, 'value', None)
            children = getattr(node, 'children', [])

            target_path = self._map_label_to_path(label)

            if target_path:
                # CAS A : Marqueur de Section
                if target_path.startswith("SECTION_"):
                    self.current_section = target_path.replace("SECTION_", "").lower()
                    if value:  # Ex: "Registrant: John Doe"
                        self._set_value(f"contacts.{self.current_section}.name", value)
                    self.process(children)

                # CAS B : Donnée identifiée
                else:
                    if value:
                        self._set_value(target_path, value)

                    for child in children:
                        if isinstance(child, str):
                            self._set_value(target_path, child)
                        else:
                            self.process([child])
            else:
                # CAS C : Inconnu -> "Other"
                if value:
                    key_name = f"{self.current_section}.{label}" if self.current_section else label
                    self.result["other"][key_name] = value
                self.process(children)

        return {k: v for k, v in self.result.items() if v}


def normalize_whois_tree_fuzzy(tree_list):
    """Fonction wrapper pour garder la compatibilité avec le reste du code."""
    engine = WhoisTreeProcessor()
    return engine.process(tree_list)