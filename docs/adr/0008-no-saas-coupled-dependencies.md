# No dependency may require an account, token or remote service

**Requirements:** F1.7 (no account, API key, token or credential to perform a scan), N2.1 (the offline Profile makes no connection — a dependency that phones a vendor would break it by construction).

valvur takes no dependency that needs credentials or transmits data to a third party
in order to function.

## Considered Options

`snyk/agent-scan` (Apache-2.0, ~3k stars, actively maintained) is the credible
off-the-shelf answer for auditing agent configurations, and we build that capability
ourselves instead. It requires `SNYK_TOKEN` and transmits component information to
Snyk's API.

## Consequences

Applying this rule to Snyk and waiving it for the next convenient tool would make the
principle meaningless, so it is absolute. It is also the rule most likely to be
challenged, because SaaS-coupled tools are frequently better than what we can build
alone.

This constrains capability. We accept a less capable check over one that breaks the
guarantee in ADR-0010, because the guarantee is the product.
