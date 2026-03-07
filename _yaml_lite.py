"""
_yaml_lite.py — Zero-dependency minimal YAML parser for RAPTOR.
Handles the subset of YAML used in config.yaml:
  - key: value
  - nested keys (indentation-based)
  - lists with  - item
  - comments (#)
  - booleans (true/false)
  - integers / floats
  - quoted strings
"""

import re
from typing import Any, Dict, List, Optional


def safe_load(text: str) -> Dict:
    """Parse a YAML string into a Python dict (safe subset only)."""
    lines = text.splitlines()
    result, _ = _parse_block(lines, 0, 0)
    return result if isinstance(result, dict) else {}


# ── helpers ────────────────────────────────────────────────────────────────

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _parse_scalar(raw: str) -> Any:
    """Convert a raw YAML scalar string to a Python value."""
    s = raw.strip()
    if not s:
        return None
    # Strip inline comment
    if ' #' in s:
        s = s[:s.index(' #')].rstrip()
    # Quoted strings
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    # Booleans
    if s.lower() in ('true', 'yes', 'on'):
        return True
    if s.lower() in ('false', 'no', 'off'):
        return False
    # Null
    if s.lower() in ('null', '~', ''):
        return None
    # Int
    try:
        return int(s)
    except ValueError:
        pass
    # Float
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _parse_block(lines: List[str], start: int, base_indent: int):
    """
    Parse a block of lines starting at `start` with expected `base_indent`.
    Returns (parsed_object, next_line_index).
    """
    result: Optional[Any] = None
    i = start

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip blanks and comments
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

        ind = _indent(line)

        # Dedented — caller's responsibility
        if ind < base_indent:
            break

        # List item
        if stripped.startswith('- ') or stripped == '-':
            if result is None:
                result = []
            item_raw = stripped[2:].strip() if stripped.startswith('- ') else ''
            if ':' in item_raw and not item_raw.startswith('"') and not item_raw.startswith("'"):
                # inline mapping inside list
                sub, i = _parse_block(lines, i, ind + 2)
                result.append(sub)
            else:
                result.append(_parse_scalar(item_raw))
                i += 1
            continue

        # Key: value
        if ':' in stripped:
            colon = stripped.index(':')
            key   = stripped[:colon].strip()
            val   = stripped[colon + 1:].strip()

            if result is None:
                result = {}

            if val:
                # Inline list  [a, b, c]
                if val.startswith('[') and val.endswith(']'):
                    items = [_parse_scalar(x.strip()) for x in val[1:-1].split(',') if x.strip()]
                    result[key] = items
                    i += 1
                else:
                    result[key] = _parse_scalar(val)
                    i += 1
            else:
                # Value is on the next line(s)
                if i + 1 < len(lines):
                    next_ind = _indent(lines[i + 1]) if lines[i + 1].strip() else ind
                    if next_ind > ind:
                        sub, i = _parse_block(lines, i + 1, next_ind)
                        result[key] = sub
                        continue
                result[key] = None
                i += 1
            continue

        i += 1

    return result, i
