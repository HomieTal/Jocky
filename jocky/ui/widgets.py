"""JOCKY Workbench UI widgets: code editor, syntax highlighter, table models."""

from __future__ import annotations

from typing import Any, List

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QRect, QSize
from PySide6.QtGui import (QColor, QFont, QPainter, QSyntaxHighlighter,
                           QTextCharFormat, QTextFormat, QPen)
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit, QWidget, QTableView

from jocky.modules.registry import ModuleRegistry

MONO_FONT = "Consolas"

# palette — serious forensic-engineering look
C_BG = "#10161d"
C_BG_PANEL = "#151d26"
C_FG = "#cfd8e3"
C_MUTED = "#6b7a8d"
C_ACCENT = "#4fc3f7"
C_KEYWORD = "#569cd6"
C_DIRECTIVE = "#c586c0"
C_STRING = "#ce9178"
C_NUMBER = "#b5cea8"
C_COMMENT = "#5a6b7d"
C_MODULE = "#4ec9b0"
C_SEVERITY = "#f48fb1"
C_ERROR = "#f48fb1"


class JockyHighlighter(QSyntaxHighlighter):
    """Syntax highlighting for .jky sources."""

    KEYWORDS = [
        "let", "const", "func", "return", "if", "elif", "else", "while",
        "foreach", "in", "break", "continue", "and", "or", "not", "true",
        "false", "null", "collect", "snapshot", "where", "sort", "by",
        "limit", "export", "alert", "baseline", "compare", "to", "print",
        "asc", "desc", "matches", "contains", "startswith", "endswith",
    ]
    SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    MODULES = ["mem", "net", "reg", "log", "disk", "sys", "processes",
               "connections", "dns_cache", "arp_table", "routing_table",
               "interfaces", "autoruns", "services", "mru", "userassist",
               "windows_events", "files", "info"]

    def __init__(self, document):
        super().__init__(document)
        self._rules = []

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        import re
        kw = "|".join(self.KEYWORDS)
        self._rules.append((re.compile(rf"\b(?:{kw})\b"), fmt(C_KEYWORD)))
        self._rules.append(
            (re.compile(r"@[a-zA-Z_]+"), fmt(C_DIRECTIVE, bold=True)))
        self._rules.append(
            (re.compile(r"\b(?:%s)\b" % "|".join(self.SEVERITIES)),
             fmt(C_SEVERITY, bold=True)))
        self._rules.append(
            (re.compile(r"\b(?:%s)\b" % "|".join(self.MODULES)), fmt(C_MODULE)))
        self._rules.append((re.compile(r"\b\d+(?:\.\d+)?\b|\b0[xXbBoO][0-9a-fA-F]+\b"),
                            fmt(C_NUMBER)))
        self._rules.append((re.compile(r"#.*$"), fmt(C_COMMENT, italic=True)))
        self._rules.append((re.compile(r"//[^\n]*"), fmt(C_COMMENT, italic=True)))
        self._rules.append((re.compile(r'"[^"\n]*"|\'[^\'\n]*\''), fmt(C_STRING)))
        self._rules.append((re.compile(r'\bf"[^"\n]*"'), fmt(C_STRING, italic=True)))

    def highlightBlock(self, text: str):  # noqa: N802 (Qt API)
        for regex, format_ in self._rules:
            match = regex.globalMatch(text) if hasattr(regex, "globalMatch") else None
            if match is not None:
                it = match
                while it.isValid():
                    self.setFormat(it.capturedStart(), it.capturedLength(), format_)
                    it = it.next()
        # multi-line block comments
        start = 0
        text_len = len(text)
        if any(self.format(i).fontItalic() and
               self.format(i).foreground().color() == QColor(C_COMMENT)
               for i in range(min(text_len, 2))) and text.startswith("/*"):
            pass
        pos = 0
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(C_COMMENT))
        comment_format.setFontItalic(True)
        while True:
            begin = text.find("/*", pos)
            if begin < 0:
                break
            end = text.find("*/", begin + 2)
            length = (end - begin + 2) if end >= 0 else text_len - begin
            self.setFormat(begin, length, comment_format)
            self.setCurrentBlockState(1 if end < 0 else 0)
            pos = begin + length
            if end < 0:
                break


class _LineNumberArea(QWidget):
    def __init__(self, editor: "CodeEditor"):
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self._editor.line_number_width(), 0)

    def paintEvent(self, event):
        self._editor.paint_line_numbers(event)


class CodeEditor(QPlainTextEdit):
    """Plain-text editor with a line-number gutter and current-line marker."""

    def __init__(self, parent=None):
        super().__init__(parent)
        font = QFont(MONO_FONT, 10)
        font.setFixedPitch(True)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._gutter = _LineNumberArea(self)
        self.blockCountChanged.connect(self._update_gutter_width)
        self.updateRequest.connect(self._update_gutter)
        self.cursorPositionChanged.connect(self._highlight_current_line)
        self._update_gutter_width()
        self._highlight_current_line()

    def line_number_width(self) -> int:
        digits = max(3, len(str(self.blockCount())))
        return 14 + self.fontMetrics().horizontalAdvance("9") * digits

    def _update_gutter_width(self, _=0):
        self.setViewportMargins(self.line_number_width(), 0, 0, 0)

    def _update_gutter(self, rect, dy):
        if dy:
            self._gutter.scroll(0, dy)
        else:
            self._gutter.update(0, rect.y(), self._gutter.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._update_gutter_width()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._gutter.setGeometry(QRect(cr.left(), cr.top(),
                                       self.line_number_width(), cr.height()))

    def paint_line_numbers(self, event):
        painter = QPainter(self._gutter)
        painter.fillRect(event.rect(), QColor("#0c1117"))
        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = round(self.blockBoundingGeometry(block).translated(
            self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())
        current = self.textCursor().blockNumber()
        painter.setPen(QColor(C_ACCENT if True else C_MUTED))
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                color = QColor(C_ACCENT) if block_number == current \
                    else QColor(C_MUTED)
                painter.setPen(color)
                painter.drawText(0, top, self._gutter.width() - 6,
                                 self.fontMetrics().height(),
                                 Qt.AlignmentFlag.AlignRight, number)
            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())
            block_number += 1

    def _highlight_current_line(self):
        selection = self.extraSelections()
        if not self.isReadOnly():
            sel = QTextEdit.ExtraSelection()
            sel.format.setBackground(QColor("#1a2530"))
            sel.format.setProperty(QTextCharFormat.Property.FullWidthSelection,
                                   True)
            sel.cursor = self.textCursor()
            sel.cursor.clearSelection()
            selection = [sel] + selection
        self.setExtraSelections(selection)


class RecordsTableModel(QAbstractTableModel):
    """Sortable table model over a list of forensic record dicts."""

    def __init__(self, rows: List[dict], columns: List[str], parent=None):
        super().__init__(parent)
        self._rows = rows
        self._columns = columns or (list(rows[0].keys()) if rows else [])
        # drop heavy nested columns from the default view
        self._columns = [c for c in self._columns
                         if not isinstance(rows[0].get(c), (list, dict))] if rows \
            else self._columns

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else max(1, len(self._columns))

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            if section < len(self._columns):
                return self._columns[section].replace("_", " ").title()
            return ""
        return section + 1

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = self._columns[index.column()] if index.column() < len(self._columns) \
            else ""
        value = row.get(col)
        if role == Qt.ItemDataRole.DisplayRole:
            if value is None:
                return "—"
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, float):
                return f"{value:g}"
            return str(value)
        if role == Qt.ItemDataRole.UserRole:
            return value
        return None

    def sort(self, column, order=Qt.SortOrder.AscendingOrder):
        if column >= len(self._columns):
            return
        col = self._columns[column]

        def key(r):
            v = r.get(col)
            if v is None:
                return (0, 0)
            if isinstance(v, bool):
                return (1, int(v))
            if isinstance(v, (int, float)):
                return (1, v)
            return (2, str(v).lower())

        self.layoutAboutToBeChanged.emit()
        self._rows.sort(key=key, reverse=order == Qt.SortOrder.DescendingOrder)
        self.layoutChanged.emit()

    def set_rows(self, rows: List[dict], columns: List[str]):
        self.beginResetModel()
        self._rows = rows
        self._columns = columns or (list(rows[0].keys()) if rows else [])
        self.endResetModel()


def style_sheet() -> str:
    return f"""
QMainWindow, QWidget {{ background: {C_BG}; color: {C_FG}; font-size: 12px; }}
QMenuBar {{ background: {C_BG_PANEL}; }}
QMenuBar::item:selected {{ background: #1d2a38; }}
QMenu {{ background: {C_BG_PANEL}; border: 1px solid #26354a; }}
QMenu::item:selected {{ background: #1d3a55; }}
QPlainTextEdit, QTextEdit {{
  background: {C_BG_PANEL}; color: {C_FG}; border: 1px solid #26354a;
  font-family: '{MONO_FONT}'; font-size: 12px; selection-background-color: #294a68;
}}
QLineEdit, QComboBox, QSpinBox {{
  background: {C_BG_PANEL}; color: {C_FG}; border: 1px solid #26354a; padding: 4px 6px;
}}
QTableView {{
  background: {C_BG_PANEL}; alternate-background-color: #18222d;
  border: 1px solid #26354a; gridline-color: #22303f; selection-background-color: #23557a;
  selection-color: #ffffff;
}}
QHeaderView::section {{
  background: #1b2836; color: {C_FG}; padding: 5px; border: 0px;
  border-right: 1px solid #26354a; border-bottom: 1px solid #2c3f55;
}}
QTabWidget::pane {{ border: 1px solid #26354a; }}
QTabBar::tab {{
  background: {C_BG_PANEL}; color: {C_MUTED}; padding: 7px 18px;
  border: 1px solid #26354a; border-bottom: none;
}}
QTabBar::tab:selected {{ color: {C_ACCENT}; background: #182430; }}
QPushButton {{
  background: #1d3a55; color: {C_FG}; border: 1px solid #2c5378;
  padding: 6px 16px; border-radius: 3px;
}}
QPushButton:hover {{ background: #24507a; }}
QPushButton:disabled {{ background: #16202b; color: #4a5a6d; border-color: #22303f; }}
QPushButton#runBtn {{ background: #1b5e20; border-color: #2e7d32; font-weight: bold; }}
QPushButton#runBtn:hover {{ background: #237a29; }}
QPushButton#dangerBtn {{ background: #5d1a1a; border-color: #8e2323; }}
QLabel#brand {{ color: {C_ACCENT}; font-size: 17px; font-weight: 800; letter-spacing: 2px; }}
QLabel#tagline {{ color: {C_MUTED}; font-size: 11px; }}
QLabel#statusLabel {{ color: {C_FG}; font-weight: 600; }}
QLabel.section {{ color: {C_ACCENT}; font-weight: 700; }}
QStatusBar {{ background: {C_BG_PANEL}; color: {C_MUTED}; }}
QSplitter::handle {{ background: #1b2836; }}
QToolTip {{ background: #1d2a38; color: {C_FG}; border: 1px solid #2c5378; }}
QCheckBox {{ color: {C_FG}; }}
"""
