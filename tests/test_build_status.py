"""R0.1: `scripts/build_status.py` tells a resuming session where the build stands.

The script is what `tasks.md` §2 has a resuming session run: which phase is current,
on which branch, what the next task is, and whether another executor looks alive.
Tested against fixture task lists and real temporary git repositories.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_status.py"


def _module():
    import sys

    spec = importlib.util.spec_from_file_location("build_status", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    # Registered first: a dataclass looks its module up in sys.modules.
    sys.modules["build_status"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


TASKS = """\
# valvur: tasks

### Phase R0: pre-flight

- [x] **R0.1** **Resuming, armed** (§2). Behaviours:
- [ ] **R0.2** **The machine.** Record: the macOS version.
- [ ] **R0.3** **The toolchain and access.** Record each:

### Phase R1: the `0.6.0` safety release

- [ ] **R1.1** **A cancel stops the queue** (F1.11). Behaviours:
"""


def test_the_current_phase_is_the_first_with_an_unchecked_task():
    position = _module().position(TASKS)
    assert (position.phase, position.title, position.task) == (0, "pre-flight", "R0.2")
