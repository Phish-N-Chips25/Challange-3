"""
Quick CUDA sanity check utility.

Run:
    python scripts/check_cuda.py
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.cuda_guard import assert_cuda_or_raise, cuda_summary


if __name__ == "__main__":
    assert_cuda_or_raise()
    print(cuda_summary())
