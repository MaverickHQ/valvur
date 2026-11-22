"""R44.10: nothing in the image says which day it was built (Requirement 22.1).

`v1.6.2`'s tree, rebuilt on 2026-11-22 and compared file by file with the image published
the day before: of 17,232 files, two differed. One was Alpine's index, which #301 took out
of the image. The other was `/etc/shadow`: `adduser` writes the day it ran as the account's
last password change, 20779 against the published 20778. CI's check builds both of its
images on one day, so it could not see it. The step that makes the account blanks the day.
"""

from __future__ import annotations

import subprocess

import pytest
from test_apk_index_not_in_image import _image, _run_steps

BLANKED = r"sed -i -E 's/^(valvur:[^:]*):[0-9]+:/\1::/' /etc/shadow"


def test_the_step_that_makes_the_account_blanks_the_day_it_ran():
    steps = [step for step in _run_steps() if "adduser" in step]

    assert len(steps) == 1, steps
    assert BLANKED in steps[0], steps[0]
    assert steps[0].index("adduser") < steps[0].index(BLANKED)


@pytest.mark.e2e
def test_the_images_account_has_no_day_of_last_change():
    line = subprocess.run(
        ["docker", "run", "--rm", "--user", "0", _image(), "grep", "^valvur:", "/etc/shadow"],
        capture_output=True, text=True, check=True).stdout.strip()

    assert line.split(":")[2] == "", line
