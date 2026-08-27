"""Compatibility entry point for CyberShield Desktop.

There used to be a second, older GUI implementation in this file.  That
implementation did not include the Security Terminal and could therefore
launch a different application from the one exposed by app.main.  Keep a
single source of truth: app.main.
"""
from app.main import main

if __name__ == "__main__":
    main()
