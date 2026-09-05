## What this changes, and why

<!-- The why matters more. What breaks if the reasoning is wrong? -->

## How you know it works

<!-- Which test would fail if this regressed? If the answer is "none", that is the
     thing to fix first. For anything load-bearing, say what you broke deliberately
     to check the test catches it. -->

## Checklist

- [ ] Tests written before the fix, and each assertion can actually fail
- [ ] `ruff check src tests` and `mypy src` pass
- [ ] `pytest -q -m "not e2e"` passes; end-to-end run if containers are touched
- [ ] The self-scan gate passes, or a suppression carries a reason and an expiry
- [ ] Spec, ADR or `CHANGELOG.md` updated if this touches a decision, a requirement,
      or anything a user sees
- [ ] No new dependency, or one justified in the description

## Anything you are unsure about

<!-- Genuinely useful. Say where you would push back on your own change. -->
