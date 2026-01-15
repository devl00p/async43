from rapidfuzz import process, fuzz

from async43.parser.constants import SCHEMA_MAPPING


def get_node_value(node):
    if node.value:
        return node.value

    if node.children:
        if isinstance(node.children[0], str):
            return " ".join(node.children)

    return ""


def normalize_whois_tree_fuzzy(tree_list):
    FLAT_CHOICES = []
    for final_key, aliases in SCHEMA_MAPPING.items():
        FLAT_CHOICES.extend(aliases)

    result = {
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

    def map_label(raw_label, current_section=None):
        if not raw_label:
            return None
        clean = raw_label.lower().replace(":", "").strip()

        # --- ÉTAPE 1 : Est-ce un changement de section ? ---
        # On cherche uniquement dans les alias commençant par SECTION_
        for final_key, aliases in SCHEMA_MAPPING.items():
            if final_key.startswith("SECTION_"):
                if clean in [a.lower() for a in aliases]:
                    return final_key

        # --- ÉTAPE 2 : Recherche avec contexte (Section actuelle) ---
        if current_section:
            # On ne cherche que parmi les clés qui commencent par la section actuelle
            choices = [k for k in SCHEMA_MAPPING.keys() if k.startswith(f"contacts.{current_section}")]
            for key in choices:
                aliases = SCHEMA_MAPPING[key]
                # Match exact d'abord
                if clean in [a.lower() for a in aliases]:
                    return key
                # Fuzzy match restreint à cette section
                res = process.extractOne(clean, aliases, scorer=fuzz.token_sort_ratio)
                if res and res[1] > 90:  # Seuil haut pour le spécifique
                    return key

        # --- ÉTAPE 3 : Recherche Globale (Si rien trouvé ou si hors section) ---
        # On évite de matcher les clés de contacts si on n'est pas dans la bonne section
        match = process.extractOne(clean, FLAT_CHOICES, scorer=fuzz.token_sort_ratio)

        if match and match[1] > 85:
            for final_key, aliases in SCHEMA_MAPPING.items():
                if match[0] in aliases:
                    # Sécurité : si on trouve un champ de contact mais qu'on n'est pas
                    # dans la bonne section, on ignore (sauf si match quasi parfait)
                    if "contacts." in final_key and current_section:
                        if not final_key.startswith(f"contacts.{current_section}") and match[1] < 95:
                            continue
                    return final_key

        return None

    def set_nested_value(dic, path, value):
        if not value or str(value).strip().lower() in ["no name servers provided", "none"]:
            return

        keys = path.split('.')
        for key in keys[:-1]:
            dic = dic.setdefault(key, {})
        target_key = keys[-1]

        value = str(value).strip()
        if target_key in ["nameservers", "status"]:
            if target_key not in dic:
                dic[target_key] = []

            if value not in dic[target_key]:
                dic[target_key].append(value)

        elif not dic.get(target_key):
            dic[target_key] = value
        else:
            if "contacts" in path and value not in dic[target_key]:
                dic[target_key] = f"{dic[target_key]}, {value}"

    def walk_tree(nodes, current_section=None):
        for node in nodes:
            label = getattr(node, 'label', "").strip()
            value = getattr(node, 'value', None)
            children = getattr(node, 'children', [])

            target_path = map_label(label, current_section)

            if target_path:
                # CAS A : C'est un marqueur de section (ex: "Registrant:")
                if target_path.startswith("SECTION_"):
                    new_section = target_path.replace("SECTION_", "").lower()

                    # Si la ligne contient une valeur (ex: Registrant: Nom),
                    # on l'assigne manuellement au champ 'name' de cette section
                    if value:
                        # On construit le chemin réel (ex: contacts.registrant.name)
                        real_path = f"contacts.{new_section}.name"
                        set_nested_value(result, real_path, value)

                    # On continue l'exploration avec le nouveau contexte
                    walk_tree(children, new_section)

                # CAS B : C'est une donnée classique
                else:
                    if value:
                        set_nested_value(result, target_path, value)

                    # Gestion des données sur plusieurs lignes (enfants strings)
                    for child in children:
                        if isinstance(child, str):
                            set_nested_value(result, target_path, child)
                        else:
                            walk_tree([child], current_section)
            else:
                # CAS C : Pas de match, on descend récursivement
                if value:
                    key_name = f"{current_section}.{label}" if current_section else label
                    result["other"][key_name] = value
                walk_tree(children, current_section)

    walk_tree(tree_list)
    return {k: v for k, v in result.items() if v}
