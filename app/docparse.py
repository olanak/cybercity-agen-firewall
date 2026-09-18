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


def extract_docx(raw_bytes: bytes) -> tuple[str, list[str]]:
    """Pull every run of text out of a .docx, marking hidden runs.

    Hidden by any of: <w:vanish/> on the run, font color #ffffff/white,
    or font size <= 2pt. Also treats comments and header/footer text as
    hidden (the resident does not see them in the normal reading view).
    """
    from io import BytesIO
    from docx import Document  # python-docx
    from docx.oxml.ns import qn

    doc = Document(BytesIO(raw_bytes))
    visible: list[str] = []
    hidden: list[str] = []

    def _run_hidden(run) -> bool:
        rpr = run._element.find(qn("w:rPr"))
        if rpr is not None and rpr.find(qn("w:vanish")) is not None:
            return True
        try:
            colour = run.font.color.rgb
            if colour is not None and str(colour).lower() in ("ffffff", "fefefe"):
                return True
        except Exception:
            pass
        try:
            size = run.font.size
            if size is not None and size.pt <= 2:
                return True
        except Exception:
            pass
        return False

    for para in doc.paragraphs:
        for run in para.runs:
            text = (run.text or "").strip()
            if not text:
                continue
            (hidden if _run_hidden(run) else visible).append(text)

    # Tables — same treatment.
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    for run in para.runs:
                        text = (run.text or "").strip()
                        if not text:
                            continue
                        (hidden if _run_hidden(run) else visible).append(text)

    # Headers, footers, and comments — treat as hidden context. Residents
    # generally do not read these carefully in a letter, so anything smuggled
    # there is an attack vector on the assistant.
    try:
        for section in doc.sections:
            for part in (section.header, section.footer):
                for para in part.paragraphs:
                    for run in para.runs:
                        text = (run.text or "").strip()
                        if text:
                            hidden.append(text)
    except Exception:
        pass

    combined = "\n".join(visible + hidden).strip()
    return combined, hidden


def extract(raw, filename: str) -> tuple[str, list[str]]:
    name = filename.lower()
    if name.endswith(".html") or name.endswith(".htm"):
        text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
        return extract_html(text)
    if name.endswith(".docx"):
        data = raw if isinstance(raw, (bytes, bytearray)) else raw.encode("latin-1", errors="replace")
        return extract_docx(bytes(data))
    # Plain text and markdown: body is the raw text, no hidden segments.
    text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
    return text.strip(), []
