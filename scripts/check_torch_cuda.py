#!/usr/bin/env python3
"""
Diagnose PyTorch + NVIDIA CUDA for Section 2 local mapper (Mistral LoRA + embedder).

Run from repo root:
  python scripts/check_torch_cuda.py

Section 2 requires a CUDA-enabled PyTorch build when ATTACK_MAPPER_REQUIRE_CUDA=true
(default). If torch.cuda.is_available() is False, install a GPU wheel from
https://pytorch.org/get-started/locally/ matching your driver, or use:
  python run_section2.py <json> --routing-mode cloud
"""

from __future__ import annotations

import shutil
import subprocess
import sys


def main() -> None:
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    print()

    try:
        import torch
    except ImportError as e:
        print("torch: NOT INSTALLED", e)
        sys.exit(1)

    print(f"torch.__version__: {torch.__version__}")
    print(f"torch.version.cuda (build): {torch.version.cuda!r}")
    cudnn = getattr(torch.backends, "cudnn", None)
    if cudnn is not None:
        print(f"torch.backends.cudnn.is_available(): {cudnn.is_available()}")
    print(f"torch.cuda.is_available(): {torch.cuda.is_available()}")

    if torch.cuda.is_available():
        n = torch.cuda.device_count()
        print(f"torch.cuda.device_count(): {n}")
        for i in range(n):
            print(f"  cuda:{i} -> {torch.cuda.get_device_name(i)}")
        try:
            x = torch.zeros(1, device="cuda:0")
            del x
            print("Smoke test: torch.zeros(1, device='cuda:0') OK")
        except Exception as exc:
            print(f"Smoke test FAILED: {exc}")
    else:
        print()
        print("CUDA is not available to PyTorch. Common causes:")
        print("  - CPU-only PyTorch (default pip install on many platforms)")
        print("  - No NVIDIA GPU, or driver not installed / too old")
        print("  - Installed CUDA wheel mismatches your driver (reinstall from pytorch.org)")
        print()
        print("Next steps:")
        print("  1) nvidia-smi  (should show your GPU and driver version)")
        print("  2) pip install torch --index-url https://download.pytorch.org/whl/cu124")
        print("     (pick cu121/cu124/cu128 etc. to match pytorch.org + your driver)")
        print("  3) Or bypass local GPU: run_section2.py ... --routing-mode cloud")

    print()
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        print("nvidia-smi: not found on PATH (driver toolkit may be missing).")
        return
    print(f"Running: {nvidia_smi}")
    try:
        out = subprocess.run(
            [nvidia_smi],
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
        print(out.stdout or out.stderr or "(no output)")
        if out.returncode != 0:
            print(f"(exit code {out.returncode})")
    except Exception as exc:
        print(f"nvidia-smi failed: {exc}")


if __name__ == "__main__":
    main()
