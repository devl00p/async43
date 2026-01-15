from rapidfuzz import process, fuzz

from async43.parser.constants import SCHEMA_MAPPING


def get_node_value(node):
    if node.value:
        return node.value

    if node.children:
        if isinstance(node.children[0], str):
            return " ".join(node.children)
        else:
            return ""
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

    def map_label(raw_label, section=None):
        if not raw_label: return None
        clean = raw_label.lower().replace(":", "").strip()

        search_query = f"{section}.{clean}" if section else clean

        match = process.extractOne(search_query, FLAT_CHOICES, scorer=fuzz.token_sort_ratio)
        if match and match[1] > 80:
            for final_key, aliases in SCHEMA_MAPPING.items():
                if match[0] in aliases:
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
            if target_key not in dic: dic[target_key] = []
            if value not in dic[target_key]: dic[target_key].append(value)
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

            potential_section = map_label(label)
            if potential_section and potential_section.startswith("SECTION_"):
                new_section = potential_section.replace("SECTION_", "").lower()
                walk_tree(children, new_section)
                continue

            target_path = map_label(label, current_section)

            if target_path:
                if value: set_nested_value(result, target_path, value)
                for child in children:
                    if isinstance(child, str):
                        set_nested_value(result, target_path, child)
                    else:
                        walk_tree([child], current_section)
            else:
                if value:
                    key_name = f"{current_section}.{label}" if current_section else label
                    result["other"][key_name] = value
                walk_tree(children, current_section)

    walk_tree(tree_list)
    return {k: v for k, v in result.items() if v}
