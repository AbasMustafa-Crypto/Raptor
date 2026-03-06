"""
_yaml_lite.py  –  Zero-dependency YAML subset parser for RAPTOR
Handles: scalars, strings, booleans, integers, floats, null,
         block mappings, block sequences, inline lists, comments.
Drop this file anywhere and do:
    from core._yaml_lite import safe_load
"""

import re
from typing import Any, Dict, List, Optional, Union


def safe_load(text: str) -> Any:
    lines = text.splitlines()
    idx, result = _parse_value(lines, 0, 0)
    return result


# ── helpers ──────────────────────────────────────────────────────────────────

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _strip_comment(s: str) -> str:
    """Remove trailing # comment (not inside quotes)."""
    in_sq = in_dq = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch == '#' and not in_sq and not in_dq:
            if i == 0 or s[i-1] in (' ', '\t'):
                return s[:i].rstrip()
    return s.rstrip()


def _cast(s: str) -> Any:
    s = s.strip()
    if s in ('', 'null', 'Null', 'NULL', '~'):
        return None
    if s in ('true', 'True', 'TRUE', 'yes', 'Yes', 'YES', 'on', 'On', 'ON'):
        return True
    if s in ('false', 'False', 'FALSE', 'no', 'No', 'NO', 'off', 'Off', 'OFF'):
        return False
    # quoted string
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    # inline list
    if s.startswith('[') and s.endswith(']'):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_cast(i.strip()) for i in _split_csv(inner)]
    # number
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s  # plain string


def _split_csv(s: str) -> List[str]:
    """Split comma-separated values respecting quotes and brackets."""
    parts, current, depth, in_sq, in_dq = [], [], 0, False, False
    for ch in s:
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch in ('[', '{') and not in_sq and not in_dq:
            depth += 1
        elif ch in (']', '}') and not in_sq and not in_dq:
            depth -= 1
        elif ch == ',' and depth == 0 and not in_sq and not in_dq:
            parts.append(''.join(current))
            current = []
            continue
        current.append(ch)
    if current:
        parts.append(''.join(current))
    return parts


# ── recursive parser ──────────────────────────────────────────────────────────

def _parse_value(lines: List[str], idx: int, base_indent: int):
    """
    Return (next_idx, parsed_value).
    Detects mapping vs sequence vs scalar by peeking at current line.
    """
    # skip blank / comment lines
    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()
        if stripped and not stripped.startswith('#'):
            break
        idx += 1

    if idx >= len(lines):
        return idx, None

    first_line = lines[idx]
    first_stripped = _strip_comment(first_line.strip())
    current_indent = _indent(first_line)

    # Block sequence  (starts with "- ")
    if first_stripped.startswith('- ') or first_stripped == '-':
        return _parse_sequence(lines, idx, current_indent)

    # Key: value pair  →  block mapping
    if re.match(r'^[^:]+:', first_stripped):
        return _parse_mapping(lines, idx, current_indent)

    # Scalar fallback
    return idx + 1, _cast(first_stripped)


def _parse_mapping(lines: List[str], idx: int, base_indent: int):
    result: Dict[str, Any] = {}

    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()

        # blank / comment
        if not stripped or stripped.startswith('#'):
            idx += 1
            continue

        current_indent = _indent(raw)

        # back-track to parent
        if current_indent < base_indent:
            break

        # sequence item inside mapping?  shouldn't happen at top-level
        if stripped.startswith('- '):
            break

        # split key: rest
        m = re.match(r'^([^:]+):\s*(.*)', stripped)
        if not m:
            idx += 1
            continue

        key = m.group(1).strip()
        rest = _strip_comment(m.group(2))

        if rest == '' or rest is None:
            # value is the next indented block
            idx += 1
            idx, value = _parse_block_value(lines, idx, current_indent)
        else:
            value = _cast(rest)
            idx += 1

        result[key] = value

    return idx, result


def _parse_sequence(lines: List[str], idx: int, base_indent: int):
    result: List[Any] = []

    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()

        if not stripped or stripped.startswith('#'):
            idx += 1
            continue

        current_indent = _indent(raw)
        if current_indent < base_indent:
            break

        if stripped.startswith('- ') or stripped == '-':
            item_text = stripped[2:].strip() if stripped.startswith('- ') else ''
            item_text = _strip_comment(item_text)

            if item_text == '' or item_text is None:
                # next block is the item value
                idx += 1
                idx, value = _parse_block_value(lines, idx, current_indent)
            elif re.match(r'^[^:]+:\s', item_text) or item_text.endswith(':'):
                # inline mapping on same line  e.g.  "- name: foo"
                fake_indent = current_indent + 2
                fake_lines = [(' ' * fake_indent) + item_text]
                # collect indented continuation
                idx += 1
                while idx < len(lines):
                    nxt = lines[idx]
                    nxt_stripped = nxt.strip()
                    if not nxt_stripped or nxt_stripped.startswith('#'):
                        fake_lines.append(nxt)
                        idx += 1
                        continue
                    if _indent(nxt) > current_indent:
                        fake_lines.append(nxt)
                        idx += 1
                    else:
                        break
                _, value = _parse_mapping(fake_lines, 0, fake_indent)
            else:
                value = _cast(item_text)
                idx += 1

            result.append(value)
        else:
            break

    return idx, result


def _parse_block_value(lines: List[str], idx: int, parent_indent: int):
    """Peek ahead to decide type of the value block."""
    # skip blank/comment
    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()
        if stripped and not stripped.startswith('#'):
            break
        idx += 1

    if idx >= len(lines):
        return idx, None

    first = lines[idx]
    fi = _indent(first)
    fs = first.strip()

    if fi <= parent_indent:
        return idx, None

    if fs.startswith('- ') or fs == '-':
        return _parse_sequence(lines, idx, fi)

    if re.match(r'^[^:]+:', fs):
        return _parse_mapping(lines, idx, fi)

    return idx + 1, _cast(_strip_comment(fs))
