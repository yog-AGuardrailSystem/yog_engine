"""Pin the current process (and, on Windows, its children) to one CPU.

Timing studies are sensitive to migration and to other work on the machine.
Pinning does not remove background load, but it removes migration noise and
makes the run reproducible.

Linux/macOS use ``os.sched_setaffinity`` where available.  Windows uses
``SetProcessAffinityMask``; child processes inherit the mask, so CLI and
harness subprocesses stay on the same core.

Usage from a driver:
    from pin import pin_cpu
    pin_cpu(args.pin_cpu)
"""
from __future__ import annotations

import os
import sys


def pin_cpu(cpu: int | None) -> str:
    """Pin to ``cpu``; return a human-readable description of what happened."""
    if cpu is None:
        return "not pinned"
    if cpu < 0:
        raise ValueError("cpu must be non-negative")

    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        handle = kernel32.GetCurrentProcess()
        kernel32.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        kernel32.SetProcessAffinityMask.restype = ctypes.c_int
        mask = 1 << cpu
        if not kernel32.SetProcessAffinityMask(handle, mask):
            error = ctypes.get_last_error()
            raise OSError(error, f"SetProcessAffinityMask failed for CPU {cpu}")
        return f"pinned to CPU {cpu} (mask 0x{mask:x}); children inherit"

    try:
        available = os.sched_getaffinity(0)
        if cpu not in available:
            raise OSError(f"CPU {cpu} is not available; have {sorted(available)}")
        os.sched_setaffinity(0, {cpu})
        return f"pinned to CPU {cpu}"
    except AttributeError:
        return "os.sched_setaffinity is unavailable; not pinned"
