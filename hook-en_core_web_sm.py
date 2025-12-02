# PyInstaller hook for spaCy models
# This ensures the en_core_web_sm model data is properly included

from PyInstaller.utils.hooks import collect_all

# Collect everything from the spaCy model
datas, binaries, hiddenimports = collect_all('en_core_web_sm')
