"""`python -m valvur.name_index {build|pull} DIR [ECOSYSTEM ...]`, and
`{build-malicious|pull-malicious} DIR [SOURCE|REFERENCE]` for the malicious list."""

import sys

from .build import _main
from .malicious import _main as _malicious

sys.exit((_malicious if sys.argv[1:2] and sys.argv[1].endswith("-malicious") else _main)(
    sys.argv[1:]))
