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

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

# bundle the web UI's static files so app.py can serve index.html from the exe
datas = [('reconpilot/web/static', 'reconpilot/web/static')]
# publicsuffixlist ships public_suffix_list.dat and loads it from disk at runtime
# (reconpilot.seeds -> registrable-domain / enumeration seeds); bundle that data.
datas += collect_data_files('publicsuffixlist')
# (tldextract is NOT used; nuclei/httpx/dnsx/etc. are EXTERNAL Go binaries, not
# Python packages, so they contribute no bundled data files.)

a = Analysis(
    # entry is the root-level wrapper (NOT reconpilot/desktop.py directly) so the
    # package is imported with context and its relative imports resolve.
    ['run_desktop.py'],
    pathex=[],
    binaries=[],
    datas=datas,
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
