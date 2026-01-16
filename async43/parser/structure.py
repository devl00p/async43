from typing import Optional, List, Union

from async43.parser.constants import LEGAL_MENTIONS


TAB_WIDTH = 4


def normalize_indent(line: str) -> tuple[int, str]:
    expanded = line.expandtabs(TAB_WIDTH)
    stripped = expanded.lstrip(" ")
    indent = len(expanded) - len(stripped)
    return indent, stripped.rstrip("\n")


def is_comment(line: str) -> bool:
    return line.lstrip().startswith(("%", ">"))


def is_blank(line: str) -> bool:
    return not line.strip()


def clean_label(label: str) -> str:
    return label.rstrip(".").strip()


def split_label_value(text: str) -> tuple[Optional[str], Optional[str]]:
    if text.startswith("[") and "]" in text:
        end = text.find("]")
        label = text[1:end].strip()
        value = text[end + 1 :].strip() or None
        return label, value

    if ":" not in text:
        return None, None

    label, rest = text.split(":", 1)

    if not label.strip():
        return None, None

    if rest == "" or rest.startswith(" "):
        label = clean_label(label)
        return label, rest.strip() or None

    return None, None


class Node:
    def __init__(self, label: str, indent: int, value: Optional[str] = None):
        self.label = label
        self.indent = indent
        self.value = value
        self.children: List[Union["Node", str]] = []

    def to_dict(self):
        return {
            "label": self.label,
            "value": self.value,
            "indent": self.indent,
            "children": [
                c.to_dict() if isinstance(c, Node) else c
                for c in self.children
            ],
        }


def parse_whois(text: str) -> List[Node]:
    lines = text.splitlines()
    root: List[Node] = []
    stack: List[Node] = []

    for raw_line in lines:
        if is_comment(raw_line) or any(m.lower() in raw_line.lower() for m in LEGAL_MENTIONS):
            continue

        indent, content = normalize_indent(raw_line)

        if is_blank(content):
            stack.clear()
            if root and root[-1].label != "SECTION_BREAK":
                root.append(Node(label="SECTION_BREAK", indent=0, value=None))
            continue

        label, value = split_label_value(content)

        if label is not None:
            node = Node(label=label, value=value, indent=indent)

            while stack and indent <= stack[-1].indent:
                stack.pop()

            if stack:
                stack[-1].children.append(node)
            else:
                root.append(node)

            stack.append(node)
        else:
            while stack and indent < stack[-1].indent:
                stack.pop()

            if stack:
                stack[-1].children.append(content)
            else:
                root.append(Node(label=content, indent=indent))

    return root
