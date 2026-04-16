"""Pytest shared config — додає корінь проекту у sys.path для імпортів."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
