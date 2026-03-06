"""
_console.py  –  Zero-dependency Rich replacement for RAPTOR
Provides: Console, Table, Panel, Progress, SpinnerColumn, TextColumn, box
All formatting is done with standard ANSI escape codes.
"""

import sys
import time
import threading
import re
from typing import List, Optional, Any


# ── ANSI colour map ────────────────────────────────────────────────────────────

_ANSI = {
    'bold':          '\033[1m',
    'dim':           '\033[2m',
    'red':           '\033[31m',
    'green':         '\033[32m',
    'yellow':        '\033[33m',
    'blue':          '\033[34m',
    'magenta':       '\033[35m',
    'cyan':          '\033[36m',
    'white':         '\033[37m',
    'bright_red':    '\033[91m',
    'bright_green':  '\033[92m',
    'bright_yellow': '\033[93m',
    'bright_blue':   '\033[94m',
    'bright_cyan':   '\033[96m',
    'bright_white':  '\033[97m',
    'reset':         '\033[0m',
}

_TAG_RE = re.compile(r'\[/?([a-zA-Z0-9_ ]+)\]')


def _render(text: str) -> str:
    """Convert [bold cyan]...[/bold cyan] markup to ANSI codes."""
    result = []
    pos = 0
    for m in _TAG_RE.finditer(text):
        result.append(text[pos:m.start()])
        tag = m.group(1).strip()
        if tag.startswith('/'):
            result.append(_ANSI['reset'])
        else:
            for part in tag.split():
                code = _ANSI.get(part.lower())
                if code:
                    result.append(code)
        pos = m.end()
    result.append(text[pos:])
    return ''.join(result) + _ANSI['reset']


def _strip(text: str) -> str:
    """Remove all markup tags, return plain text."""
    return _TAG_RE.sub('', text)


# ── Box styles ─────────────────────────────────────────────────────────────────

class _Box:
    ROUNDED   = {'tl':'╭','tr':'╮','bl':'╰','br':'╯','h':'─','v':'│','lm':'├','rm':'┤','tm':'┬','bm':'┴','c':'┼'}
    DOUBLE_EDGE = {'tl':'╔','tr':'╗','bl':'╚','br':'╝','h':'═','v':'║','lm':'╠','rm':'╣','tm':'╦','bm':'╩','c':'╬'}
    SIMPLE    = {'tl':'+','tr':'+','bl':'+','br':'+','h':'-','v':'|','lm':'+','rm':'+','tm':'+','bm':'+','c':'+'}

box = type('box', (), {
    'ROUNDED':     _Box.ROUNDED,
    'DOUBLE_EDGE': _Box.DOUBLE_EDGE,
    'SIMPLE':      _Box.SIMPLE,
})()


# ── Console ────────────────────────────────────────────────────────────────────

class Console:
    def __init__(self, no_color: bool = False):
        self.no_color = no_color

    def print(self, *args, **kwargs):
        text = ' '.join(str(a) for a in args)
        if self.no_color:
            sys.stdout.write(_strip(text) + '\n')
        else:
            sys.stdout.write(_render(text) + '\n')
        sys.stdout.flush()


# ── Table ──────────────────────────────────────────────────────────────────────

class Table:
    def __init__(self, title: str = '', box=None, **kwargs):
        self.title = title
        self.box_style = box or _Box.SIMPLE
        self._cols: List[dict] = []
        self._rows: List[List[str]] = []

    def add_column(self, header: str, style: str = '', justify: str = 'left', **kw):
        self._cols.append({'header': header, 'style': style, 'justify': justify})

    def add_row(self, *cells):
        self._rows.append([str(c) for c in cells])

    def __str__(self) -> str:
        b = self.box_style
        # calculate column widths
        widths = [len(_strip(c['header'])) for c in self._cols]
        for row in self._rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(_strip(cell)))

        def hline(left, mid, right, fill):
            parts = [fill * (w + 2) for w in widths]
            return left + mid.join(parts) + right

        lines = []
        if self.title:
            total = sum(widths) + 3 * len(widths) - 1
            lines.append(_render(f'[bold]{self.title}[/bold]'))

        lines.append(hline(b['tl'], b['tm'], b['tr'], b['h']))

        # header
        header_cells = []
        for i, col in enumerate(self._cols):
            plain = _strip(col['header'])
            pad = widths[i] - len(plain)
            header_cells.append(f" {_render('[bold]' + col['header'] + '[/bold]')}{' ' * pad} ")
        lines.append(b['v'] + b['v'].join(header_cells) + b['v'])
        lines.append(hline(b['lm'], b['c'], b['rm'], b['h']))

        for row in self._rows:
            cells = []
            for i in range(len(self._cols)):
                cell = row[i] if i < len(row) else ''
                plain_len = len(_strip(cell))
                pad = widths[i] - plain_len
                rendered = _render(cell)
                if self._cols[i]['justify'] == 'right':
                    cells.append(f"{' ' * (pad + 1)}{rendered} ")
                else:
                    cells.append(f" {rendered}{' ' * pad} ")
            lines.append(b['v'] + b['v'].join(cells) + b['v'])

        lines.append(hline(b['bl'], b['bm'], b['br'], b['h']))
        return '\n'.join(lines)


# ── Panel ──────────────────────────────────────────────────────────────────────

class Panel:
    def __init__(self, content: str, box=None, title: str = '', **kwargs):
        self.content = content
        self.box_style = box or _Box.ROUNDED
        self.title = title

    @classmethod
    def fit(cls, content: str, box=None, **kwargs):
        return cls(content, box=box, **kwargs)

    def __str__(self) -> str:
        b = self.box_style
        plain_lines = _strip(self.content).splitlines()
        width = max((len(l) for l in plain_lines), default=40) + 2

        top = b['tl'] + b['h'] * width + b['tr']
        bot = b['bl'] + b['h'] * width + b['br']

        rendered_lines = []
        for line in self.content.splitlines():
            plain = _strip(line)
            rendered = _render(line)
            pad = width - 2 - len(plain)
            rendered_lines.append(b['v'] + ' ' + rendered + ' ' * max(pad, 0) + ' ' + b['v'])

        return '\n'.join([top] + rendered_lines + [bot])


# ── Progress (spinner) ─────────────────────────────────────────────────────────

class SpinnerColumn:
    pass

class TextColumn:
    def __init__(self, fmt: str = '', **kw):
        self.fmt = fmt

class _Task:
    def __init__(self, tid: int, description: str):
        self.id = tid
        self.description = description
        self.completed = False

class Progress:
    _FRAMES = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']

    def __init__(self, *columns, console: Optional[Console] = None, **kwargs):
        self._console = console or Console()
        self._tasks: List[_Task] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._frame = 0
        self._lock = threading.Lock()

    def __enter__(self):
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        # clear spinner line
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()

    def add_task(self, description: str, total=None, **kw) -> int:
        with self._lock:
            tid = len(self._tasks)
            self._tasks.append(_Task(tid, description))
        return tid

    def update(self, task_id: int, completed: bool = False, **kw):
        with self._lock:
            if task_id < len(self._tasks):
                self._tasks[task_id].completed = completed
                if completed:
                    desc = _strip(self._tasks[task_id].description)
                    sys.stdout.write('\r' + ' ' * 80 + '\r')
                    sys.stdout.write(_render(f'[green]✓[/green] {desc}\n'))
                    sys.stdout.flush()

    def _spin(self):
        while self._running:
            with self._lock:
                active = [t for t in self._tasks if not t.completed]
                if active:
                    desc = _strip(active[-1].description)
                    frame = self._FRAMES[self._frame % len(self._FRAMES)]
                    sys.stdout.write(f'\r{frame} {desc}   ')
                    sys.stdout.flush()
                    self._frame += 1
            time.sleep(0.1)
