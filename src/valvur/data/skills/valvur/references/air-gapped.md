# Offline and air-gapped machines

A scan on the `offline` Profile, the default, gives its Scanners no network. What
it reads comes from this machine's cache: the vulnerability database, the
package-name index and its malicious list, CISA KEV, FIRST's EPSS scores, and OSV's
offline database for each ecosystem the project's lockfiles use.

- **Stale data.** A scan refreshes data past its age limit as it fetches absent
  data, and says so in its progress. When the verdict's reason names old data, call
  `update` with `if_stale`, then scan again. The fetches carry nothing of the project.
- **A machine that must never fetch.** `fetch = "never"` in
  `~/.config/valvur/config.toml` (or `VALVUR_FETCH=never`) stops every fetch a scan
  would make on its own. A scan then reads what the cache holds, and a scan that
  finds nothing on stale data is `inconclusive`. Say that, and never report it as
  clean.
- **Mirrors.** Each source has a mirror setting (`db_repository`,
  `index_repository`, `kev_url`, `epss_url`, `osv_url`). `valvur doctor --network`
  makes one connection per configured source and nothing else; `valvur update`
  fetches from the mirrors. The full guide is `docs/AIR-GAPPED.md` in valvur's
  repository.
- **`full`.** The `full` Profile asks the network what local data cannot answer:
  OSV.dev, and the registries for package age and adoption. They receive package
  names and versions, never source. Use it only when the human asks.

`valvur doctor` says which setting came from where. When a scan fails on a machine
like this, call `doctor` and relay its lines as they are.
