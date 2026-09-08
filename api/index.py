import sys
from pathlib import Path

# Add root directory to python path so it imports main.py properly
root_path = Path(__file__).resolve().parent.parent
sys.path.append(str(root_path))

from main import app