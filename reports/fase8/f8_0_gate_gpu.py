#!/usr/bin/env python3
"""F8.0 gate check: GPU + CUDA availability for PyTorch in WSL2."""
import torch

cuda_ok = torch.cuda.is_available()
print(f"torch.__version__ = {torch.__version__}")
print(f"torch.version.cuda = {torch.version.cuda}")
print(f"torch.cuda.is_available() = {cuda_ok}")

if cuda_ok:
    idx = torch.cuda.current_device()
    print(f"torch.cuda.get_device_name({idx}) = {torch.cuda.get_device_name(idx)}")
    props = torch.cuda.get_device_properties(idx)
    print(f"total_memory_gb = {props.total_memory / (1024**3):.2f}")

GATE_PASS = cuda_ok and "4070" in (torch.cuda.get_device_name(0) if cuda_ok else "")
print(f"GATE_F8_0_PASS = {GATE_PASS}")
