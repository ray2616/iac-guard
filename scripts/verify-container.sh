#!/bin/bash
set -euo pipefail
python -m pip install --no-cache-dir --target /tmp/test-deps -c requirements-linux.lock.txt pytest
python -m alembic upgrade head
python -m alembic check
python -m pytest --basetemp=/tmp/pytest -o cache_dir=/tmp/pytest-cache --junitxml=/results/pytest-linux.xml
