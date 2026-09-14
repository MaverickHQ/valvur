# valvur's own Checks run inside the container

> **Note (2026-08-31):** the Profile named here has been renamed. `quick` is now
> `offline` and is the default; `standard` and `deep` are now the single `full`
> Profile. See [ADR-0016](0016-two-profiles-split-on-the-network-boundary.md).


**Checks** — detection valvur performs itself — execute inside the scanner image
exactly as third-party **Scanners** do. They are invoked as
`python -m valvur.checks <name> /workspace`, emit JSON on stdout, and the host parses
it into **Findings**.

## Considered Options

**Run Checks host-side, in the shim.** Simpler, faster, and no image rebuild when
Check code changes. Rejected because the Dependency Reality **Check** makes registry
API calls: host-side, those sit entirely outside the container's `--network=none`,
and the guarantee in ADR-0010 reverts from a property to a policy. A reviewer could
no longer verify non-exfiltration by inspecting how the container is launched.

## Consequences

Running in-container makes F3.5 structural rather than remembered. On the `quick`
**Profile** there is no network interface, so the Dependency Reality **Check**
*cannot* reach a registry and reports **skipped** — the honest degradation we wanted,
enforced by the architecture instead of by a code path someone might later change.

**No new orchestrator protocol was needed.** Because Checks run in the container and
emit JSON, they fit the existing adapter contract exactly: `run` invokes the
container, `parse` reads the output. Checks therefore inherit failure isolation,
Profile selection, concurrency and **Provenance** from the fleet at no cost. The
`Check` protocol describes what a Check implements *inside* the container; the
orchestrator sees only adapters.

Adapters carry `kind` — `"scanner"` or `"check"` — and it is not cosmetic. We credit
Scanners by name and licence (P4), and must never imply that detection we perform
ourselves came from a third-party tool, nor the reverse.

Checks return plain dicts rather than **Findings**, so **Redaction** and
**Fingerprint** derivation stay on the host side of the boundary, in one place.

The cost is that changing Check code requires an image rebuild. The package is copied
in the final layer, so that rebuild is seconds.

## Amendment 2026-09-14 (task 23.4.2): the Checks share one container

Measured with per-Scanner timing (23.3.2): each Check cost 12–16s on a Mac and
2–3s on Linux for milliseconds of work — a container start of a 576MB image and an
interpreter start, three times a scan. Now `python -m valvur.checks batch` runs the
selected Checks in **one** container, and the orchestrator plans one task for them
(`api._plan`) that yields one outcome per Check. Nothing about the contract above
changes: three ScannerRuns, three lines of provenance, three coverage contracts, each
Check's findings under its own name, each Check's failure its own (the batch keeps
them apart, and a refusal inside it costs nothing to the others). What changes is
the count of container starts — nine a scan became seven — and, measured on the
fixture on a loaded Mac, about four seconds off every scan, most of it Checkov and
Opengrep no longer contending with two more container starts.

The isolation argument holds because the Checks are our code. The only network any
of them ever had is dependency-reality's, on `full`; the batch container carries the
Profile's grant — the widest any Check in it was given, which is that one's — and
runs dependency-reality last. On `offline` the batch has no interface at all, as
each Check's container had. A runner that cannot batch, or a scan with one Check
selected, runs them one by one as before.

"No new orchestrator protocol" still holds for adapters: `CheckAdapter` is unchanged.
The orchestrator gained an internal notion — a task may answer for several adapters
— and the runner gained `run_checks` beside `run_check`.

