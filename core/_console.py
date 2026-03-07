"""
_console.py — Zero-dependency Rich-like console for RAPTOR.
Provides: Console, Table, Panel, Progress, SpinnerColumn, TextColumn, box
All terminal output works with plain Python stdlib (sys, shutil, itertools).
"""

import sys
import shutil
import itertools
import threading
import time
import re
from typing import List, Optional, Any


# ── Markup stripper ─────────────────────────────────────────────────────────

_MARKUP_RE = re.compile(r'\[/?[^\[\]]*\]')

def _strip(text: str) -> str:
    """Remove [bold], [/red], etc. markup tags."""
    return _MARKUP_RE.sub('', str(text))


# ── ANSI colour map ──────────────────────────────────────────────────────────

_ANSI = {
    'bold':       '\033[1m',
    'dim':        '\033[2m',
    'red':        '\033[31m',
    'green':      '\033[32m',
    'yellow':     '\033[33m',
    'blue':       '\033[34m',
    'cyan':       '\033[36m',
    'white':      '\033[37m',
    'bright_red': '\033[91m',
    '/':          '\033[0m',   # reset (used for closing tags)
}
_RESET = '\033[0m'

def _apply_markup(text: str) -> str:
    """Convert [cyan]...[/cyan] markup to ANSI codes."""
    def replace(m: re.Match) -> str:
        tag = m.group(0)[1:-1]          # strip [ ]
        if tag.startswith('/'):
            return _RESET
        parts = tag.split()
        codes = ''.join(_ANSI.get(p, '') for p in parts)
        return codes
    return _MARKUP_RE.sub(replace, str(text)) + _RESET


# ── box ──────────────────────────────────────────────────────────────────────

class _Box:
    DOUBLE_EDGE = 'double'
    ROUNDED     = 'rounded'
    SIMPLE      = 'simple'

box = _Box()


# ── Panel ────────────────────────────────────────────────────────────────────

class Panel:
    def __init__(self, text: str, box=None):
        self.text = text
        self._box = box

    @staticmethod
    def fit(text: str, box=None) -> 'Panel':
        return Panel(text, box)

    def __str__(self) -> str:
        lines   = [_strip(l) for l in self.text.splitlines()]
        width   = min(max((len(l) for l in lines), default=0) + 4, 80)
        top     = '╔' + '═' * (width - 2) + '╗'
        bottom  = '╚' + '═' * (width - 2) + '╝'
        rows    = [top]
        for l in lines:
            rows.append('║ ' + l.ljust(width - 4) + ' ║')
        rows.append(bottom)
        return '\n'.join(rows)


# ── Table ────────────────────────────────────────────────────────────────────

class Table:
    def __init__(self, title: str = '', box=None):
        self.title   = title
        self._box    = box
        self._cols:  List[dict] = []
        self._rows:  List[List[str]] = []

    def add_column(self, header: str, style: str = '', justify: str = 'left'):
        self._cols.append({'header': header, 'style': style, 'justify': justify})

    def add_row(self, *cells):
        self._rows.append([_strip(str(c)) for c in cells])

    def __str__(self) -> str:
        headers = [c['header'] for c in self._cols]
        widths  = [len(h) for h in headers]
        for row in self._rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(_strip(cell)))

        def row_str(cells: List[str]) -> str:
            parts = []
            for i, cell in enumerate(cells):
                w    = widths[i] if i < len(widths) else 10
                just = self._cols[i]['justify'] if i < len(self._cols) else 'left'
                s    = _strip(cell)
                parts.append(s.rjust(w) if just == 'right' else s.ljust(w))
            return '│ ' + ' │ '.join(parts) + ' │'

        sep  = '├' + '┼'.join('─' * (w + 2) for w in widths) + '┤'
        top  = '╭' + '┬'.join('─' * (w + 2) for w in widths) + '╮'
        bot  = '╰' + '┴'.join('─' * (w + 2) for w in widths) + '╯'

        lines = []
        if self.title:
            lines.append(self.title)
        lines.append(top)
        lines.append(row_str(headers))
        lines.append(sep)
        for row in self._rows:
            lines.append(row_str(row + [''] * (len(self._cols) - len(row))))
        lines.append(bot)
        return '\n'.join(lines)


# ── Progress / Spinner ────────────────────────────────────────────────────────

class SpinnerColumn:
    _frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    def __init__(self):
        self._iter = itertools.cycle(self._frames)
    def next_frame(self) -> str:
        return next(self._iter)

class TextColumn:
    def __init__(self, template: str):
        self.template = template
    def render(self, description: str) -> str:
        return _strip(self.template.replace('{task.description}', description))


class _Task:
    def __init__(self, description: str):
        self.description = description
        self.completed   = False


class Progress:
    """Context-manager spinner that writes to stderr."""

    def __init__(self, *columns, console=None):
        self._columns   = columns
        self._tasks:    List[_Task] = []
        self._stop      = threading.Event()
        self._thread:   Optional[threading.Thread] = None
        self._lock      = threading.Lock()

    def __enter__(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        sys.stderr.write('\r' + ' ' * 80 + '\r')
        sys.stderr.flush()

    def add_task(self, description: str, total=None) -> int:
        with self._lock:
            idx = len(self._tasks)
            self._tasks.append(_Task(_strip(description)))
        return idx

    def update(self, task_id: int, completed=False, description: str = ''):
        with self._lock:
            if task_id < len(self._tasks):
                if completed:
                    self._tasks[task_id].completed = True
                    # Print completion marker
                    sys.stderr.write('\r✓ ' + self._tasks[task_id].description + '\n')
                    sys.stderr.flush()
                if description:
                    self._tasks[task_id].description = _strip(description)

    def _spin(self):
        spinner_col = next((c for c in self._columns if isinstance(c, SpinnerColumn)), SpinnerColumn())
        while not self._stop.is_set():
            frame = spinner_col.next_frame()
            with self._lock:
                active = [t for t in self._tasks if not t.completed]
                desc   = active[-1].description if active else ''
            line = f'\r{frame} {desc[:70]}'
            sys.stderr.write(line)
            sys.stderr.flush()
            time.sleep(0.1)


# ── Console ───────────────────────────────────────────────────────────────────

class Console:
    """Drop-in for rich.console.Console."""

    def print(self, *args, **kwargs):
        text = ' '.join(str(a) for a in args)
        # Render panel objects directly
        if len(args) == 1 and isinstance(args[0], Panel):
            print(str(args[0]))
            return
        if len(args) == 1 and isinstance(args[0], Table):
            print(str(args[0]))
            return
        # Strip markup for plain output, or apply ANSI if terminal
        if sys.stdout.isatty():
            print(_apply_markup(text))
        else:
            print(_strip(text))
