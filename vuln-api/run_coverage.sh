#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Run pytest with coverage for the `app` package and emit XML report
# Use `python3 -m pytest` so the interpreter's installed packages are used.
python3 -m pytest --cov=app --cov-report=xml:coverage.xml -q

echo "Coverage XML generated at: $(pwd)/coverage.xml"