import runpy
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent / "Sentinel-A2A"
sys.path.insert(0, str(project_root))
runpy.run_path(str(project_root / "frontend" / "app.py"), run_name="__main__")
