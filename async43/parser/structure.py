from typing import Optional, List, Union

from async43.parser.constants import LEGAL_MENTIONS


TAB_WIDTH = 4


def normalize_indent(line: str) -> tuple[int, str]:
    """
    Normalize indentation for a single line.

    Tabs are expanded using a fixed tab width, leading spaces are counted
    to determine the indentation level, and the trailing newline is removed.

    :param line: Raw input line.
    :return: A tuple containing:
             - the indentation level (number of leading spaces)
             - the line content stripped of leading indentation and trailing newline
    """
    expanded = line.expandtabs(TAB_WIDTH)
    stripped = expanded.lstrip(" ")
    indent = len(expanded) - len(stripped)
    return indent, stripped.rstrip("\n")


def is_comment(line: str) -> bool:
    """
    Determine whether a line should be treated as a comment.

    A line is considered a comment if, after left-stripping whitespace,
    it starts with '%' or '>'.

    :param line: Input line.
    :return: True if the line is a comment, False otherwise.
    """
    return line.lstrip().startswith(("%", ">"))


def is_blank(line: str) -> bool:
    """
    Determine whether a line is blank or contains only whitespace.

    :param line: Input line.
    :return: True if the line is empty or whitespace-only, False otherwise.
    """
    return not line.strip()


def clean_label(label: str) -> str:
    """
    Normalize a label by removing trailing dots and surrounding whitespace.

    :param label: Raw label string.
    :return: Cleaned label.
    """
    return label.rstrip(".").strip()


def split_label_value(text: str) -> tuple[Optional[str], Optional[str]]:
    """
    Split a line into a label and an optional value.

    Supported formats:
    - "[Label] value"
    - "Label: value"

    If the line cannot be interpreted as a label/value pair,
    (None, None) is returned.

    :param text: Line content without indentation.
    :return: A tuple (label, value), where each element may be None.
    """
    if text.startswith("[") and "]" in text:
        end = text.find("]")
        label = text[1:end].strip()
        value = text[end + 1:].strip() or None
        return label, value

    if ":" not in text:
        return None, None

    label, rest = text.split(":", 1)

    if not label.strip():
        return None, None

    label = clean_label(label)
    return label, rest.strip() or None


class Node:
    """
    Represents a parsed WHOIS node.

    A node corresponds to a labeled field, optionally associated with a value,
    and may contain nested child nodes or raw text lines.
    """

    def __init__(self, label: str, indent: int, value: Optional[str] = None):
        """
        Create a new Node.

        :param label: Field label.
        :param indent: Indentation level of the node.
        :param value: Optional field value.
        """
        self.label = label
        self.indent = indent
        self.value = value
        self.children: List[Union["Node", str]] = []

    def to_dict(self) -> dict:
        """
        Convert the node and its children into a dictionary representation.

        :return: A dictionary containing the node's label, value, indentation,
                 and recursively converted children.
        """
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
    """
    Parse raw WHOIS text into a hierarchical tree of nodes.

    The parser uses indentation to infer parent/child relationships,
    ignores comment lines and legal mentions, and inserts explicit
    section breaks when blank lines are encountered.

    :param text: Raw WHOIS response text.
    :return: A list of top-level Node objects representing the parsed structure.
    """
    lines = text.splitlines()
    root: List[Node] = []
    stack: List[Node] = []

    for raw_line in lines:
        if is_comment(raw_line) or any(
            m.lower() in raw_line.lower() for m in LEGAL_MENTIONS
        ):
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
