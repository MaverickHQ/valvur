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
