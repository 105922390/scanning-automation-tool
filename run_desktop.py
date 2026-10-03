"""Root-level entry point for the packaged desktop app (PyInstaller).

PyInstaller runs its entry script as the top-level module ``__main__`` with no
package context, so ``reconpilot/desktop.py``'s relative imports can't resolve if
used as the entry directly. This wrapper imports the package normally instead.
``python -m reconpilot.desktop`` keeps working unchanged.
"""

from reconpilot.desktop import main

if __name__ == "__main__":
    raise SystemExit(main())
