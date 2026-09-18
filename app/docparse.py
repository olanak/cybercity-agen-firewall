"""Extract text from uploaded documents.

For HTML we walk the DOM and pull *all* text — visible and hidden —
tagging spans that are hidden (display:none, color matching background,
tiny font sizes, or inside HTML comments). Hidden text is what an
attacker uses to smuggle instructions, so it must not be silently dropped.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser


HIDDEN_STYLE_PATTERNS = [
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.I),
    re.compile(r"font-size\s*:\s*0(?:px)?\b", re.I),
    re.compile(r"font-size\s*:\s*1px\b", re.I),
    re.compile(r"color\s*:\s*#?fff(?:fff)?\b", re.I),
    re.compile(r"color\s*:\s*white\b", re.I),
]


def _style_is_hidden(style: str) -> bool:
    return any(p.search(style) for p in HIDDEN_STYLE_PATTERNS)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: list[str] = []
        # stack of booleans: True means the current subtree is hidden.
        self._hidden_stack: list[bool] = [False]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        style = ""
        for name, value in attrs:
            if name == "style" and value:
                style = value
        hidden_here = self._hidden_stack[-1] or _style_is_hidden(style)
        if tag == "script" or tag == "style":
            hidden_here = True
        self._hidden_stack.append(hidden_here)

    def handle_endtag(self, tag: str) -> None:
        if len(self._hidden_stack) > 1:
            self._hidden_stack.pop()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # e.g. <br/> — no push/pop
        pass

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text:
            return
        if self._hidden_stack[-1]:
            self.hidden.append(text)
        else:
            self.visible.append(text)

    def handle_comment(self, data: str) -> None:
        text = data.strip()
        if text:
            self.hidden.append(text)


def extract_html(raw: str) -> tuple[str, list[str]]:
    p = _Extractor()
    p.feed(raw)
    p.close()
    combined = "\n".join(p.visible + p.hidden).strip()
    return combined, list(p.hidden)


def extract(raw: str, filename: str) -> tuple[str, list[str]]:
    name = filename.lower()
    if name.endswith(".html") or name.endswith(".htm"):
        return extract_html(raw)
    # Plain text and markdown: body is the raw text, no hidden segments.
    return raw.strip(), []
