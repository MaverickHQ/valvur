"""`python -m valvur.name_index {build|pull} DIR [ECOSYSTEM ...]`."""

import sys

from .build import _main

sys.exit(_main(sys.argv[1:]))
