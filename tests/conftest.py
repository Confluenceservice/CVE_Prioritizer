import sys
from pathlib import Path

# Make the repo root importable so `scripts` resolves when pytest is run
# from any directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
