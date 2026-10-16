"""Root entrypoint for Streamlit Community Cloud deployment.

Allows Streamlit Community Cloud to run either from the standard root entrypoint
(streamlit_app.py) or from src/ui/app.py seamlessly.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is on sys.path
_repo_root = Path(__file__).resolve().parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from src.ui.app import main

if __name__ == "__main__":
    main()
