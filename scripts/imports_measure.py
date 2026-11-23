#!/usr/bin/env python3
"""What DefectDojo and Dependency-Track keep of a Results Folder (R51.5, D82p, Requirement 9).

    python3 scripts/imports_measure.py defectdojo --url http://localhost:8080 \\
        --password-file FILE --results DIR
    python3 scripts/imports_measure.py dependency-track --url http://localhost:8081 \\
        --password-file FILE --results DIR

Each sends the artifact as a user's own pipeline would, through the tool's own API, and reads
back what arrived: `results.sarif` into DefectDojo, `sbom.cdx.json` into Dependency-Track.
Then it sends the same file again, to see whether the tool counts it twice. The report is
JSON on stdout: what was sent, what arrived, and each field that did not arrive as sent.

valvur never uploads (Requirement 9.4): this is the build's measurement, outside the
package, against tools it starts for the purpose. Standard library alone. Exit 0 when the
report was written, 2 when a tool could not be reached or refused the import.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from pathlib import Path

#: SARIF's key for valvur's Fingerprint, as `artifacts.py` writes it.
FINGERPRINT_KEY = "valvurFingerprint/v1"
PRODUCT = "valvur imports"
WAIT_S = 300


class Unreachable(RuntimeError):
    pass


def call(method: str, url: str, *, headers: dict[str, str] | None = None,
         body: bytes | None = None) -> tuple[int, bytes]:
    if not url.startswith(("http://", "https://")):
        raise Unreachable(f"{url}: not an http or https address")
    request = urllib.request.Request(  # noqa: S310 - the scheme is checked above
        url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
        raise Unreachable(f"{method} {url}: {error}") from error


def multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]
              ) -> tuple[bytes, str]:
    """A multipart/form-data body and its content type."""
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
                     f"{value}\r\n".encode())
    for name, (filename, content, kind) in files.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
                     f'filename="{filename}"\r\nContent-Type: {kind}\r\n\r\n'.encode()
                     + content + b"\r\n")
    return (b"".join(parts) + f"--{boundary}--\r\n".encode(),
            f"multipart/form-data; boundary={boundary}")


def _json(status: int, body: bytes, what: str) -> dict:
    if status >= 300:
        raise Unreachable(f"{what}: HTTP {status}: {body[:300].decode(errors='replace')}")
    return json.loads(body or b"{}")


# ------------------------------------------------------------------ what was sent

def sent_sarif(results: Path) -> list[dict]:
    """One entry per SARIF location, which is what DefectDojo makes a finding of: the
    Fingerprint, the path and line, and what valvur said of the Finding."""
    sarif = json.loads((results / "results.sarif").read_text(encoding="utf-8"))
    findings = {f["fingerprint"]: f for f in json.loads(
        (results / "findings.json").read_text(encoding="utf-8"))["findings"]}
    [run] = sarif["runs"]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    sent = []
    for result in run["results"]:
        fingerprint = result["partialFingerprints"][FINGERPRINT_KEY]
        finding = findings[fingerprint]
        properties = rules[result["ruleId"]].get("properties") or {}
        suppressions = result.get("suppressions") or []
        # An ignore of the project's own that valvur did not accept: a property since
        # R51.7, and before it a suppression with `status: rejected`.
        ignored = (result.get("properties") or {}).get("ignoredBy") or {}
        if any(s.get("status") == "accepted" for s in suppressions):
            said = "accepted"
        elif suppressions or ignored:
            said = "not accepted"
        else:
            said = None
        for location in result["locations"]:
            physical = location["physicalLocation"]
            sent.append({
                "fingerprint": fingerprint, "rule": result["ruleId"],
                "path": physical["artifactLocation"]["uri"],
                "line": (physical.get("region") or {}).get("startLine"),
                "severity": finding["severity"],
                "cwe": list(finding.get("cwe") or []),
                "owasp": list(finding.get("owasp") or []),
                "tags": list(properties.get("tags") or []),
                # Live unless valvur accepted it.
                "live": said != "accepted", "suppression": said,
            })
    return sent


# ------------------------------------------------------------------ DefectDojo

_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
             "info": "Info"}


def _dojo_findings(url: str, auth: dict[str, str], test: int) -> list[dict]:
    found: list[dict] = []
    page: str | None = f"{url}/api/v2/findings/?test={test}&limit=500"
    while page:
        reply = _json(*call("GET", page, headers=auth), "listing the findings")
        found += reply["results"]
        page = reply.get("next")
    return found


def _dojo_import(url: str, auth: dict[str, str], sarif: bytes, engagement: str,
                 *, into: int | None = None) -> int:
    """Send the file: as a new test of the engagement, or again `into` a test it made."""
    fields = {"scan_type": "SARIF", "minimum_severity": "Info"}
    if into is None:
        fields |= {"product_type_name": "valvur", "product_name": PRODUCT,
                   "engagement_name": engagement, "auto_create_context": "true"}
    else:
        fields["test"] = str(into)
    body, kind = multipart(fields, {"file": ("results.sarif", sarif, "application/json")})
    endpoint = "import-scan" if into is None else "reimport-scan"
    reply = _json(*call("POST", f"{url}/api/v2/{endpoint}/",
                        headers={**auth, "Content-Type": kind}, body=body), endpoint)
    return int(reply.get("test") or reply["test_id"])


def _dojo_duplicates(url: str, auth: dict[str, str], test: int, *, wait: bool) -> dict:
    """A test's findings and how many DefectDojo marked as duplicates. It marks them in
    a task of its own after the import answers, so with deduplication on this waits."""
    deadline = time.monotonic() + WAIT_S
    while True:
        found = _dojo_findings(url, auth, test)
        marked = sum(1 for one in found if one.get("duplicate"))
        if not wait or marked == len(found) or time.monotonic() > deadline:
            return {"findings": len(found), "marked_duplicate": marked}
        time.sleep(10)


def _cwes(finding: dict) -> list[int]:
    """Every CWE DefectDojo holds for a finding: `cwe`, a number, and `cwes`, a list of
    `{"cwe": "CWE-n"}`."""
    given = [finding.get("cwe"), *(extra.get("cwe") if isinstance(extra, dict) else extra
                                   for extra in finding.get("cwes") or [])]
    numbers = [int(str(one).upper().removeprefix("CWE-")) for one in given if one]
    return list(dict.fromkeys(numbers))


def defectdojo(url: str, password: str, results: Path, *, user: str = "admin") -> dict:
    url = url.rstrip("/")
    token = _json(*call("POST", f"{url}/api/v2/api-token-auth/",
                        headers={"Content-Type": "application/json"},
                        body=json.dumps({"username": user, "password": password}).encode()),
                  "the API token")["token"]
    auth = {"Authorization": f"Token {token}"}
    sarif = (results / "results.sarif").read_bytes()
    sent = sent_sarif(results)
    engagement = f"measured {int(time.time())}"

    first = _dojo_import(url, auth, sarif, engagement)
    arrived = _dojo_findings(url, auth, first)
    # DefectDojo reads the key `valvurFingerprint/v1` as a name and a version, and keeps
    # `<name>:<value>`.
    name = FINGERPRINT_KEY.split("/")[0]
    by_id = {(a.get("unique_id_from_tool"), a.get("file_path")): a for a in arrived
             if a.get("unique_id_from_tool")}
    without: dict[tuple, list[dict]] = {}
    for a in arrived:
        if not a.get("unique_id_from_tool"):
            without.setdefault((a.get("vuln_id_from_tool"), a.get("file_path"),
                                a.get("line") or None), []).append(a)

    def arrived_for(one: dict) -> dict | None:
        """By the Fingerprint where it arrived. Else by rule, path and line, among the
        findings that arrived without one: whether it arrives is one thing measured."""
        got = by_id.get((f"{name}:{one['fingerprint']}", one["path"]))
        rest = without.get((one["rule"], one["path"], one["line"]))
        return got or (rest.pop() if rest else None)

    lost: dict[str, list[dict]] = {key: [] for key in (
        "not_arrived", "no_unique_id", "severity", "cwe", "line", "live_arrived_inactive",
        "owasp_tag")}
    accepted: Counter[str] = Counter()
    for one in sent:
        got = arrived_for(one)
        if got is None:
            lost["not_arrived"].append({"rule": one["rule"], "path": one["path"]})
            continue
        where = {"rule": one["rule"], "path": one["path"]}
        if got.get("unique_id_from_tool") != f"{name}:{one['fingerprint']}":
            lost["no_unique_id"].append({**where, "arrived": got.get("unique_id_from_tool")})
        if one["suppression"] == "accepted":
            accepted[f"active={got.get('active')} false_p={got.get('false_p')} "
                     f"risk_accepted={got.get('risk_accepted')}"] += 1
        if got.get("severity") != _SEVERITY.get(one["severity"], "Medium"):
            lost["severity"].append({**where, "sent": one["severity"],
                                     "arrived": got.get("severity")})
        wanted = [int(c.split("-")[1]) for c in one["cwe"]]
        if wanted and not set(wanted) <= set(_cwes(got)):
            lost["cwe"].append({**where, "sent": one["cwe"], "arrived": _cwes(got)})
        if one["line"] and got.get("line") != one["line"]:
            lost["line"].append({**where, "sent": one["line"], "arrived": got.get("line")})
        if one["live"] and not got.get("active"):
            lost["live_arrived_inactive"].append({**where, "suppression": one["suppression"],
                                                  "false_p": got.get("false_p")})
        tags = [str(t).lower() for t in got.get("tags") or []]
        if one["owasp"] and not all(any(o.lower() in t for t in tags) for o in one["owasp"]):
            lost["owasp_tag"].append({**where, "sent": one["owasp"], "arrived": tags})

    # The same file again, three ways. A pipeline that counts it twice doubles a team's
    # backlog every night.
    # 1. Into the test it made, which is what DefectDojo's re-import is for.
    _dojo_import(url, auth, sarif, engagement, into=first)
    after = _dojo_findings(url, auth, first)
    before = {a["id"]: a for a in arrived}
    reimport = {"findings": len(after),
                "new": len({a["id"] for a in after} - set(before)),
                "closed_by_it": sum(1 for a in after if a.get("is_mitigated")
                                    and not (before.get(a["id"]) or {}).get("is_mitigated")),
                "active_before": sum(1 for a in arrived if a.get("active")),
                "active_after": sum(1 for a in after if a.get("active"))}
    # 2. As a second import, with deduplication as the install has it.
    [settings] = _json(*call("GET", f"{url}/api/v2/system_settings/", headers=auth),
                       "the system settings")["results"]
    default = bool(settings.get("enable_deduplication"))
    second = _dojo_duplicates(url, auth, _dojo_import(url, auth, sarif, engagement),
                              wait=default)
    # 3. As another import with deduplication on, where the install has it off.
    third = None
    if not default:
        _json(*call("PATCH", f"{url}/api/v2/system_settings/{settings['id']}/",
                    headers={**auth, "Content-Type": "application/json"},
                    body=json.dumps({"enable_deduplication": True}).encode()),
              "turning deduplication on")
        third = _dojo_duplicates(url, auth, _dojo_import(url, auth, sarif, engagement),
                                 wait=True)
    return {
        "tool": "DefectDojo",
        "sent": {"results": len({s["fingerprint"] for s in sent}), "locations": len(sent),
                 "live": sum(1 for s in sent if s["live"]),
                 "accepted": sum(1 for s in sent if s["suppression"] == "accepted"),
                 "ignores_not_accepted": sum(1 for s in sent
                                             if s["suppression"] == "not accepted"),
                 "by_severity": dict(Counter(s["severity"] for s in sent)),
                 "with_cwe": sum(1 for s in sent if s["cwe"]),
                 "with_owasp": sum(1 for s in sent if s["owasp"]),
                 "with_line": sum(1 for s in sent if s["line"])},
        "arrived": {"findings": len(arrived),
                    "active": sum(1 for a in arrived if a.get("active")),
                    "false_positive": sum(1 for a in arrived if a.get("false_p")),
                    "by_severity": dict(Counter(a.get("severity") for a in arrived)),
                    "with_cwe": sum(1 for a in arrived if _cwes(a)),
                    "with_tags": sum(1 for a in arrived if a.get("tags")),
                    "with_line": sum(1 for a in arrived if a.get("line")),
                    "with_file": sum(1 for a in arrived if a.get("file_path")),
                    "with_unique_id": sum(1 for a in arrived if a.get("unique_id_from_tool")),
                    "with_vulnerability_id": sum(1 for a in arrived
                                                 if a.get("vulnerability_ids"))},
        "lost": {key: {"count": len(value), "examples": value[:5]}
                 for key, value in lost.items()},
        "accepted_arrived_as": dict(accepted),
        "reimport_into_the_same_test": reimport,
        "second_import": {**second, "deduplication_on_by_default": default},
        "import_with_deduplication_on": third,
        "example": {key: arrived[0].get(key) for key in (
            "title", "severity", "cwe", "tags", "file_path", "line", "unique_id_from_tool",
            "vuln_id_from_tool", "active", "false_p", "component_name")}
        if arrived else None,
    }


# ------------------------------------------------------------------ Dependency-Track

def _track_components(url: str, auth: dict[str, str], project: str) -> list[dict]:
    found, page = [], 1
    while True:
        status, body = call("GET", f"{url}/api/v1/component/project/{project}"
                                   f"?pageSize=500&pageNumber={page}", headers=auth)
        batch = json.loads(body) if status < 300 else None
        if batch is None:
            raise Unreachable(f"listing the components: HTTP {status}: {body[:200]!r}")
        found += batch
        if len(batch) < 500:
            return found
        page += 1


def _track_upload(url: str, auth: dict[str, str], sbom: bytes, version: str) -> None:
    body, kind = multipart({"autoCreate": "true", "projectName": PRODUCT,
                            "projectVersion": version},
                           {"bom": ("sbom.cdx.json", sbom, "application/vnd.cyclonedx+json")})
    token = _json(*call("POST", f"{url}/api/v1/bom", headers={**auth, "Content-Type": kind},
                        body=body), "the BOM upload")["token"]
    deadline = time.monotonic() + WAIT_S
    while time.monotonic() < deadline:
        state = _json(*call("GET", f"{url}/api/v1/event/token/{token}", headers=auth),
                      "the upload's state")
        if not state.get("processing"):
            return
        time.sleep(5)
    raise Unreachable(f"the BOM was still being processed after {WAIT_S} s")


#: What a pipeline's key needs: to upload, to make the project it uploads to, and for this
#: measurement to read back what arrived.
TEAM = "Automation"
NEEDED = ("BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO")


def _track_key(url: str, admin: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """An API key on the team an install ships for pipelines, as a person would make one
    in its interface, and what that team was permitted before anything was granted."""
    teams = _json(*call("GET", f"{url}/api/v1/team", headers=admin), "the teams")
    team = next((one for one in teams if one.get("name") == TEAM), None)
    if team is None:
        team = _json(*call("PUT", f"{url}/api/v1/team",
                           headers={**admin, "Content-Type": "application/json"},
                           body=json.dumps({"name": TEAM}).encode()), "making the team")
    had = sorted(str(p.get("name")) for p in team.get("permissions") or [])
    for permission in NEEDED:
        if permission not in had:
            status, body = call("POST", f"{url}/api/v1/permission/{permission}/team/"
                                        f"{team['uuid']}", headers=admin)
            if status >= 400:
                raise Unreachable(f"granting {permission}: HTTP {status}: {body[:200]!r}")
    made = _json(*call("PUT", f"{url}/api/v1/team/{team['uuid']}/key", headers=admin),
                 "the API key")
    return {"X-Api-Key": str(made["key"])}, had


def _licence(component: dict) -> str:
    resolved = component.get("resolvedLicense") or {}
    return str(resolved.get("licenseId") or component.get("licenseExpression")
               or component.get("license") or "")


def dependency_track(url: str, password: str, results: Path) -> dict:
    """`password` is what the fresh install's admin is given in place of the one every
    install starts with: made by the caller for this run, and gone with the container."""
    url = url.rstrip("/")
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    # A fresh install makes its first user change the password. Refused once it has been.
    call("POST", f"{url}/api/v1/user/forceChangePassword", headers=form,
         body=urllib.parse.urlencode({"username": "admin", "password": "admin",
                                      "newPassword": password,
                                      "confirmPassword": password}).encode())
    status, body = call("POST", f"{url}/api/v1/user/login", headers=form,
                        body=urllib.parse.urlencode({"username": "admin",
                                                     "password": password}).encode())
    if status >= 300:
        raise Unreachable(f"the login: HTTP {status}: {body[:200]!r}")
    # The admin's session makes the key. Everything after it is done with the key alone,
    # as a pipeline does it.
    auth, had = _track_key(url, {"Authorization": f"Bearer {body.decode().strip()}"})
    version = _json(*call("GET", f"{url}/api/version"), "the version").get("version")

    sbom_path = results / "sbom.cdx.json"
    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    sent = document.get("components") or []
    run = f"measured-{int(time.time())}"
    _track_upload(url, auth, sbom_path.read_bytes(), run)
    lookup = urllib.parse.urlencode({"name": PRODUCT, "version": run})
    project = _json(*call("GET", f"{url}/api/v1/project/lookup?{lookup}", headers=auth),
                    "the project")
    arrived = _track_components(url, auth, project["uuid"])

    def named(component: dict, kind: str) -> tuple[str, str, str]:
        return (str(component.get(kind) or "").lower(), str(component.get("name") or ""),
                str(component.get("version") or ""))

    there = {named(c, "classifier") for c in arrived}
    not_arrived = [dict(zip(("type", "name", "version"), named(c, "type"), strict=True))
                   for c in sent if named(c, "type") not in there]
    # Two lockfiles that pin one package give two components with one purl.
    sent_purls = {c["purl"] for c in sent if c.get("purl")}
    arrived_purls = {c["purl"] for c in arrived if c.get("purl")}
    sent_licensed = [c for c in sent if c.get("licenses")]
    _track_upload(url, auth, sbom_path.read_bytes(), run)
    again = _track_components(url, auth, project["uuid"])
    return {
        "tool": "Dependency-Track", "version": version,
        "key": {"team": TEAM, "permitted_as_installed": had, "needed": list(NEEDED)},
        "sent": {"spec_version": document.get("specVersion"), "components": len(sent),
                 "with_purl": sum(1 for c in sent if c.get("purl")),
                 "distinct_purls": len(sent_purls), "with_licence": len(sent_licensed),
                 "with_hashes": sum(1 for c in sent if c.get("hashes")),
                 "by_type": dict(Counter(c.get("type") for c in sent))},
        "arrived": {"components": len(arrived),
                    "with_purl": sum(1 for c in arrived if c.get("purl")),
                    "distinct_purls": len(arrived_purls),
                    "with_licence": sum(1 for c in arrived if _licence(c)),
                    "with_hashes": sum(1 for c in arrived
                                       if any(c.get(h) for h in ("md5", "sha1", "sha256"))),
                    "by_classifier": dict(Counter(c.get("classifier") for c in arrived))},
        "lost": {"components_not_arrived": not_arrived[:10],
                 "purls_not_arrived": sorted(sent_purls - arrived_purls)[:10],
                 "purls_not_sent": sorted(arrived_purls - sent_purls)[:10],
                 "components_without_purl_sent": sum(1 for c in sent if not c.get("purl"))},
        "second_upload": {"components": len(again)},
        "example": {key: arrived[0].get(key) for key in (
            "name", "version", "purl", "classifier", "licenseExpression", "license")}
        if arrived else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tool", choices=["defectdojo", "dependency-track"])
    parser.add_argument("--url", required=True)
    parser.add_argument("--results", required=True, type=Path, help="a Results Folder")
    parser.add_argument("--password-file", type=Path, required=True,
                        help="DefectDojo: the admin password its own initializer printed. "
                             "Dependency-Track: one made for this run, which the fresh "
                             "install's admin is given")
    args = parser.parse_args(argv)
    password = args.password_file.read_text(encoding="utf-8").strip()
    try:
        if args.tool == "defectdojo":
            made = defectdojo(args.url, password, args.results)
        else:
            made = dependency_track(args.url, password, args.results)
    except (Unreachable, KeyError, ValueError) as error:
        print(f"imports: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(made, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
