"""Source-checkout CLI using the canonical PDF writer embedded by the desktop app."""
import runpy
from pathlib import Path
if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).resolve().parents[1] / 'src-tauri' / 'src' / 'pdf_report.py'), run_name='__main__')
