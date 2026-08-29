from __future__ import annotations
import threading
from app.security.background_guard import BackgroundProtection
from app.security.phishing_service import PhishingGuardService
def main():
    guard=BackgroundProtection(interval=2.0,clipboard=True); service=PhishingGuardService(); guard.start(); threading.Thread(target=service.start,daemon=True).start()
    try:
        while True: threading.Event().wait(60)
    except KeyboardInterrupt:
        guard.stop(); service.stop()
if __name__=='__main__': main()
