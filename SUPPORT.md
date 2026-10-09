# Getting help with valvur

valvur is free software maintained by one person ([MAINTAINERS.md](MAINTAINERS.md)). There
is no paid tier and no support contract, and every channel below is public except the one
for vulnerabilities.

| you have | go to |
|---|---|
| a question, an idea, or something to show | [Discussions](https://github.com/MaverickHQ/valvur/discussions) |
| a bug, a finding you think is wrong, or one valvur **missed** | [an issue](https://github.com/MaverickHQ/valvur/issues/new/choose), with the tarball `valvur doctor --bundle` writes |
| a suspected vulnerability in valvur, a false `clean` included | a private report, as [SECURITY.md](SECURITY.md) says; never a public issue |

## Before you ask

- **`valvur doctor`** says whether this machine can scan, and what to install or start if it
  cannot. Most first-run problems end there.
- **The guides** answer the rest: [the command line](docs/CLI.md), [AI coding agents](docs/AGENTS.md),
  [CI](docs/CI.md), and [how valvur works](docs/HOW-IT-WORKS.md).
- **A scan that reads `inconclusive`** says why in one line, `status_reason` in `run.json`.
  It is valvur declining to call a result `clean` that it cannot support, not a failure.

## What the bundle holds

`valvur doctor --bundle` writes a tarball to attach to an issue: this machine's doctor
report, the versions of everything involved, and the last scan's `run.json`. It never holds
your source, the Scanners' raw output, or your findings. Read it before you attach it; it
is yours.

## What to expect

Issues and discussions are answered as the maintainer can; there is no response-time
commitment outside security reports.
Security reports have the commitments in [SECURITY.md](SECURITY.md): an acknowledgement
within five working days and an assessment within fifteen.
