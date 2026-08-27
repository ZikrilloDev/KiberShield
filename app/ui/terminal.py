"""CyberShield Security Terminal UI.

This widget is deliberately backed by the real CyberShieldTerminal command
layer instead of a second shell implementation. Commands run off the Qt UI
thread so host inspection/scanning cannot freeze the desktop application.
"""
from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt, QEvent
from PySide6.QtGui import QFont, QTextCursor, QColor
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QLabel, QPushButton

from app.ai.cybershield_terminal import CyberShieldTerminal
from app.i18n import get_language


class _CommandWorker(QObject):
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, terminal: CyberShieldTerminal, command: str):
        super().__init__()
        self.terminal = terminal
        self.command = command

    @Slot()
    def run(self):
        try:
            result = self.terminal.execute(self.command)
            self.finished.emit(result or "")
        except Exception as exc:
            self.failed.emit(f"ERROR: {type(exc).__name__}: {exc}")


class TerminalWidget(QWidget):
    """Real CyberShield security terminal, not a generic OS shell."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.terminal = CyberShieldTerminal(get_language())
        self._thread: QThread | None = None
        self._worker: _CommandWorker | None = None
        self._history_index = -1
        self._build_ui()
        self._append(self.terminal.help_text(), "#00f0ff")

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("CYBERSHIELD SECURITY TERMINAL")
        title.setStyleSheet("font-size:18px;font-weight:700;")
        layout.addWidget(title)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        self.console.setStyleSheet(
            "QTextEdit{background:#0b0e14;color:#00f0ff;border:1px solid #263040;"
            "border-radius:8px;padding:10px;}"
        )
        layout.addWidget(self.console, 1)

        row = QHBoxLayout()
        self.prompt = QLabel("CyberShield>")
        self.prompt.setStyleSheet("color:#00ff66;font-weight:700;font-family:Consolas;")
        self.input = QLineEdit()
        self.input.setPlaceholderText('Masalan: tizim | jarayonlar | tekshir "C:\\sample.exe" | xesh "C:\\sample.exe"')
        self.input.returnPressed.connect(self.submit)
        self.run_button = QPushButton("RUN")
        self.run_button.clicked.connect(self.submit)
        self.clear_button = QPushButton("CLEAR")
        self.clear_button.clicked.connect(self.clear)
        row.addWidget(self.prompt)
        row.addWidget(self.input, 1)
        row.addWidget(self.run_button)
        row.addWidget(self.clear_button)
        layout.addLayout(row)
        self.input.installEventFilter(self)

    def _append(self, text: str, color: str = "#00f0ff"):
        self.console.moveCursor(QTextCursor.End)
        self.console.setTextColor(QColor(color))
        self.console.insertPlainText(text + ("" if text.endswith("\n") else "\n"))
        self.console.moveCursor(QTextCursor.End)
        self.console.ensureCursorVisible()

    @Slot()
    def submit(self):
        command = self.input.text().strip()
        if not command or self._thread is not None:
            return
        self.input.clear()
        self._history_index = -1
        self._append(f"CyberShield> {command}", "#ffffff")

        # clear is handled locally so the UI responds instantly.
        if command.lower() in {"clear", "toza", "РѕС‡РёСЃС‚РёС‚СЊ"}:
            self.clear()
            return

        self.input.setEnabled(False)
        self.run_button.setEnabled(False)
        self._append("[CyberShield] Tekshirilmoqda...", "#00ff66")

        self._thread = QThread(self)
        self._worker = _CommandWorker(self.terminal, command)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._thread_done)
        self._thread.start()

    @Slot(str)
    def _on_finished(self, result: str):
        if result:
            if result == "__CLEAR__":
                self.console.clear()
            else:
                self._append(result, "#00f0ff")

    @Slot(str)
    def _on_failed(self, message: str):
        self._append(message, "#ff3366")

    @Slot()
    def _thread_done(self):
        if self._thread:
            self._thread.deleteLater()
        if self._worker:
            self._worker.deleteLater()
        self._thread = None
        self._worker = None
        self.input.setEnabled(True)
        self.run_button.setEnabled(True)
        self.input.setFocus()

    def clear(self):
        self.console.clear()
        self._append(self.terminal.help_text(), "#00f0ff")

    def set_language(self, code: str):
        self.terminal.set_language(code)
        if self._thread is None:
            self.prompt.setText("CyberShield>")

    def eventFilter(self, obj, event):
        if obj is self.input and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key_Up and self.terminal.history:
                if self._history_index < len(self.terminal.history) - 1:
                    self._history_index += 1
                idx = len(self.terminal.history) - 1 - self._history_index
                self.input.setText(self.terminal.history[idx])
                return True
            if event.key() == Qt.Key_Down and self.terminal.history:
                if self._history_index > 0:
                    self._history_index -= 1
                    idx = len(self.terminal.history) - 1 - self._history_index
                    self.input.setText(self.terminal.history[idx])
                else:
                    self._history_index = -1
                    self.input.clear()
                return True
        return super().eventFilter(obj, event)

