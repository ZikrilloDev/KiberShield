"""CyberShield unified entry point: Desktop, CIBER terminal and background guard."""
from __future__ import annotations
import sys, threading, time

def _run_live(term, command: str):
    from app.ai.ciber_cli import live_thinking
    stop = threading.Event()
    result = {"value": None}
    started = time.monotonic()
    def worker():
        try:
            result["value"] = term.execute(command)
        except BaseException as exc:
            result["value"] = f"ERROR: {type(exc).__name__}: {exc}"
        finally:
            stop.set()
    threading.Thread(target=worker, name="ciber-action", daemon=True).start()
    live_thinking("CIBER working", stop, started)
    # wait for the worker without allowing a renderer to overwrite input
    while not stop.is_set():
        time.sleep(0.02)
    return result["value"] or ""

def _run_ciber_mode_once(term, line: str) -> str:
    out = _run_live(term, "ciber " + line.strip())
    return "" if out == "__CLEAR__" else out

def _ciber_banner():
    from app.ai.ciber_cli import animate_start
    animate_start()

def _run_ciber_mode(term, initial: str | None = None):
    _ciber_banner()
    if initial:
        out = _run_ciber_mode_once(term, initial)
        if out: print(out)
    while True:
        try:
            from app.ai.ciber_cli import ciber_prompt
            line = input(ciber_prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if line.lower() in {"exit","quit","back","ortga","chiqish"}:
            return
        if not line:
            continue
        out = _run_live(term, "ciber " + line)
        if out == "__CLEAR__":
            print()
        elif out:
            print(out)

def _run_desktop(panel=None):
    from app.main import main
    main(initial_panel=panel)
    return 0

if __name__ == "__main__":
    mode=(sys.argv[1] if len(sys.argv)>1 else "desktop").strip().lower()
    if mode in {"desktop","cibershield","cybershield"}:
        panel=None
        if "--panel" in sys.argv:
            i=sys.argv.index("--panel")
            if i+1 < len(sys.argv): panel=sys.argv[i+1]
        raise SystemExit(_run_desktop(panel))
    if mode in {"ciber","cyber","ciber-terminal","ciber_terminal"}:
        from app.ai.cybershield_terminal import CyberShieldTerminal
        term=CyberShieldTerminal()
        initial=" ".join(sys.argv[2:]).strip()
        _run_ciber_mode(term, initial or None)
        raise SystemExit(0)
    if mode in {"terminal","security-terminal","security_terminal"}:
        from app.ai.cybershield_terminal import CyberShieldTerminal
        term=CyberShieldTerminal()
        command=" ".join(sys.argv[2:]) if len(sys.argv)>2 else None
        if command and command.strip().lower().split()[0] in {"ciber","cyber","ciber-terminal"}:
            parts=command.strip().split(maxsplit=1)
            if len(parts)>1: print(_run_ciber_mode_once(term,parts[1]))
            _run_ciber_mode(term); raise SystemExit(0)
        if command: print(term.execute(command))
        else:
            print(term.help_text())
            while True:
                try: line=input("CyberShield> ").strip()
                except (EOFError,KeyboardInterrupt): print(); break
                if line.lower() in {"exit","quit","chiqish","выход"}: break
                if line.lower() in {"ciber","ciber mode","ciber-mode"}:
                    _run_ciber_mode(term); continue
                out=term.execute(line)
                if out and out!="__CLEAR__": print(out)
        raise SystemExit(0)
    if mode=="background":
        from app.security.background_guard import BackgroundProtection
        guard=BackgroundProtection(); guard.start()
        print("CyberShield background protection started. Press Ctrl+C to stop.")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            try: guard.stop()
            except Exception: pass
        raise SystemExit(0)
    print("CyberShield unified launcher")
    print("Usage: ciber | cibershield | python main.py [desktop|ciber|terminal|background]")
    raise SystemExit(2)
