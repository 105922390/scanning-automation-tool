# PyInstaller spec — build a single ReconPilot.exe bundling the app + static files.
#
#   pip install pyinstaller
#   pyinstaller reconpilot.spec
#   -> dist/ReconPilot.exe
#
# NOTE: the Go recon tools (subfinder, amass, dnsx, httpx, nuclei, …) remain
# EXTERNAL dependencies. They are NOT bundled — the packaged app shells out to
# whatever is on PATH, exactly like the CLI. tools.yaml and the engagements/
# directory are also external (read from the working directory at runtime), so the
# user keeps editing them without rebuilding the exe.
#
# This bundles only the Python app and its web static assets. The window is the
# existing web UI via pywebview (see reconpilot/desktop.py:main).

block_cipher = None

a = Analysis(
    ['reconpilot/desktop.py'],
    pathex=[],
    binaries=[],
    # bundle the web UI's static files so app.py can serve index.html from the exe
    datas=[('reconpilot/web/static', 'reconpilot/web/static')],
    hiddenimports=[
        'uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan.on',
        'webview',           # pywebview; its platform backend is picked at runtime
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ReconPilot',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=False,        # GUI app: no console window
    icon='reconpilot/web/static/icon.ico' if __import__('os').path.exists(
        'reconpilot/web/static/icon.ico') else None,
)
