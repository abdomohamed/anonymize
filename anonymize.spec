# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for PII Anonymization Tool

This spec file configures how PyInstaller bundles the application.
It includes all necessary data files, spaCy models, and dependencies.
"""

import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules
from pathlib import Path

block_cipher = None

# Collect all data files from presidio
presidio_data = collect_data_files('presidio_analyzer', include_py_files=True)
presidio_data += collect_data_files('presidio_anonymizer', include_py_files=True)

# Add presidio conf files explicitly
import os
import presidio_analyzer
presidio_path = os.path.dirname(presidio_analyzer.__file__)
presidio_conf_path = os.path.join(presidio_path, 'conf')
if os.path.exists(presidio_conf_path):
    presidio_data += [(presidio_conf_path, 'presidio_analyzer/conf')]

# Collect spaCy data and models
spacy_data = collect_data_files('spacy')
spacy_data += collect_data_files('en_core_web_sm')

# Collect all submodules
hidden_imports = []
hidden_imports += collect_submodules('presidio_analyzer')
hidden_imports += collect_submodules('presidio_anonymizer')
hidden_imports += collect_submodules('spacy')
hidden_imports += collect_submodules('en_core_web_sm')
hidden_imports += collect_submodules('faker')
hidden_imports += collect_submodules('yaml')
hidden_imports += ['yaml', 'pyyaml']

# Include your source files and config
src_files = [
    ('src', 'src'),
    ('config/default_config.yaml', 'config'),
]

# Combine all data files
datas = presidio_data + spacy_data + src_files

a = Analysis(
    ['src/cli.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=['.'],  # Look for hooks in current directory
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
    name='anonymize',
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
    # Icon for the executable (optional)
    # icon='icon.ico',
)
