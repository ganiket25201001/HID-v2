PYTHON ?= python

ifeq ($(wildcard .venv/Scripts/python.exe),.venv/Scripts/python.exe)
PYTHON := .venv/Scripts/python.exe
endif

ifeq ($(wildcard .venv/bin/python),.venv/bin/python)
PYTHON := .venv/bin/python
endif

PIP ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
PYINSTALLER ?= $(PYTHON) -m PyInstaller

.DEFAULT_GOAL := run

.PHONY: run clean build-exe install-deps test

install-deps:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

run:
	$(PYTHON) main.py

build-exe:
	$(PYINSTALLER) build.spec

test:
	$(PYTEST) -q

clean:
	$(PYTHON) -c "import pathlib, shutil; root=pathlib.Path('.'); dirs=['build','dist','.pytest_cache','.mypy_cache','.ruff_cache','htmlcov']; [shutil.rmtree(root/d, ignore_errors=True) for d in dirs]; [shutil.rmtree(p, ignore_errors=True) for p in root.rglob('__pycache__')]; [p.unlink(missing_ok=True) for p in root.rglob('*.pyc')]; [p.unlink(missing_ok=True) for p in root.rglob('*.pyo')]; [p.unlink(missing_ok=True) for p in [root/'.coverage', root/'hid_shield.log']]"
