# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None
requirements = []

with open(os.path.join(os.path.dirname(os.getcwd()), 'requirements.txt')) as f:
    for r in f.read().splitlines():
        requirements.append(r.split('=')[0])

requirements.append('ipaddress')

a = Analysis(
    ['driver.py'],
    pathex=[],
    binaries=[],
    datas=[('forensic', 'forensic')],
    hiddenimports=requirements,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
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
    name='driver',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
