from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLineEdit
from PySide6.QtCore import Signal, QObject
from PySide6.QtGui import QFont, QTextCursor
from app.core.terminal_engine import RealTerminalEngine

class TerminalSignal(QObject):
    append_text = Signal(str)

class RealTerminalWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signals = TerminalSignal()
        self.engine = RealTerminalEngine(output_callback=self._on_output_received)

        self._init_ui()
        self.signals.append_text.connect(self._append_to_console)

    def _init_ui(self):
        layout = QVBoxLayout(self)
        
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background-color: #0d1117; color: #00ff66; font-family: Consolas; font-size: 13px;")

        self.input_field = QLineEdit()
        self.input_field.setStyleSheet("background-color: #161b22; color: #ffffff; font-family: Consolas; padding: 4px;")
        self.input_field.setPlaceholderText("Buyruqni kiriting...")
        self.input_field.returnPressed.connect(self._process_input)

        layout.addWidget(self.console)
        layout.addWidget(self.input_field)

        self._append_to_console("CyberShield Real Terminal v2.0\n> ")

    def _process_input(self):
        command = self.input_field.text()
        if not command.strip():
            return

        self._append_to_console(f"{command}\n")
        self.input_field.clear()

        if command.strip().lower() in ["cls", "clear"]:
            self.console.clear()
            self._append_to_console("> ")
            return

        self.engine.run_command(command)

    def _on_output_received(self, text: str):
        self.signals.append_text.emit(text)

    def _append_to_console(self, text: str):
        self.console.moveCursor(QTextCursor.End)
        self.console.insertPlainText(text)
        self.console.moveCursor(QTextCursor.End)