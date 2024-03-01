import sys
from cx_Freeze import setup, Executable

# Lista de archivos y carpetas a incluir
included_files = [
    ("Icons/", "Icons"),  # Puedes renombrar el archivo si lo deseas
    ("config.ini", "config.ini"),         # También puedes incluir carpetas enteras
]

# Dependencies are automatically detected, but it might need fine tuning.
build_exe_options = {
    "excludes": ["unittest"],
    "zip_include_packages": ["encodings", "PySide6"],
    "include_files": included_files,  # Agrega tus archivos y carpetas aquí
}

# base="Win32GUI" should be used only for Windows GUI app
base = "Win32GUI" if sys.platform == "win32" else None

setup(
    name="Montra",
    version="0.1",
    description="App Mavesa",
    options={"build_exe": build_exe_options},
    executables=[Executable("Montra.py", base=base, icon="Icons/logo-montra.ico")],
)