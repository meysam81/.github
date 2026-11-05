#!/usr/bin/env python3
"""Static verdict for a dependency PR: what it changes, and whether it looks safe.

  verdict.py plan --head DIR --base DIR
  verdict.py run  --head DIR --base DIR --flux-root k8s/prod-eu --out DIR

Static only: it never reads release notes or boots the new version, so most
majors end up as "review". "safe" is deliberately narrow.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

GROUPS = {
    "k8s": r"^k8s/",
    "ansible": r"^(playbooks|roles|inventory)/|^(requirements\.(yml|txt)|ansible\.cfg|main\.yml)$",
    "tofu": r"^tofu/",
    "nix": r"^flake\.(nix|lock)$",
    "poetry": r"^(poetry\.lock|pyproject\.toml)$",
    "bun": r"^(bun\.lock|package\.json)$",
}
# Merging these deploys nothing: someone has to run them.
HAND_RUN = r"^(scripts|tofu|playbooks|roles|inventory)/|^requirements\.yml$"
SAFE_UPDATES = {"digest", "pin", "pinDigest", "patch", "lockFileMaintenance", "lockfile"}
STATEFUL_KINDS = {"StatefulSet", "DaemonSet", "Cluster"}
WORKLOADS = STATEFUL_KINDS | {"Deployment"}
# ponytail: one amd64 fleet; make this an input if arm64 nodes ever join.
PLATFORM = ("linux", "amd64")
# A catalog revision, not a branch: a schema change should arrive as a PR.
CRD_CATALOG = "https://raw.githubusercontent.com/datreeio/CRDs-catalog/{sha}/{{{{.Group}}}}/{{{{.ResourceKind}}}}_{{{{.ResourceAPIVersion}}}}.json"
CRD_CATALOG_SHA = "6ab3493622cd387923a2d0da5234f53e80e1bd28"
COMMENT_LIMIT = 60_000  # GitHub caps a comment at 65,536 characters


def sh(cmd, cwd=None, timeout=600):
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, text=True, errors="replace",
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout
    except FileNotFoundError:
        return 127, f"{cmd[0]} is not installed"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]} timed out after {timeout}s"


def tail(text, n=400):
    return " ".join(text.split())[-n:]


def check(name, status, detail=""):
    return {"name": name, "status": status, "detail": detail}


def differential(name, cmd, head, base, cwd="."):
    """A failure only blocks if main passes: old breakage is not this PR's fault."""
    rc, out = sh(cmd, Path(head) / cwd)
    if rc == 0:
        return check(name, "pass")
    if sh(cmd, Path(base) / cwd)[0] != 0:
        return check(name, "warn", f"also fails on main: {tail(out, 200)}")
    return check(name, "fail", tail(out))


def changed_files(head, base):
    rc, out = sh(["git", "diff", "--name-only", sh(["git", "rev-parse", "HEAD"], base)[1].strip(), "HEAD"], head)
    if rc:
        sys.exit(f"git diff failed: {out}")
    return [f for f in out.splitlines() if f]


def groups_for(files):
    return {g for g, pat in GROUPS.items() if any(re.search(pat, f) for f in files)}


def semver_type(change):
    """`1.19.2` -> `1.19.9` is patch. Grouped Renovate tables have no Update column."""
    found = re.findall(r"(\d+)\.(\d+)(?:\.(\d+))?", change)
    if len(found) < 2:
        return "unknown"
    old, new = found[0], found[-1]
    return "major" if old[0] != new[0] else "minor" if old[1] != new[1] else "patch"


def update_types(title, body):
    """The update kinds from the first table of a Renovate PR body."""
    if "lock file maintenance" in title.lower():
        return {"lockFileMaintenance"}
    header, types = None, set()
    for line in (body or "").split("This PR contains the following updates:")[-1].splitlines():
        if not line.startswith("|"):
            if header:
                break
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            header = cells
        elif not set(line) <= set("|-: "):
            row = dict(zip(header, cells))
            types.add(row["Update"] if row.get("Update") else semver_type(row.get("Change", "")))
    return types


def parse_diff(diff):
    """Objects and images from `flate diff -o diff`."""
    objects, old, new = [], set(), set()
    for line in diff.splitlines():
        if m := re.match(r"^(?:---|\+\+\+) ([A-Z]\w+) (\S+)$", line):
            if (m[1], m[2]) not in objects:
                objects.append((m[1], m[2]))
        elif m := re.match(r"^([-+])\s+(?:- )?image: ['\"]?([^\s'\"]+)", line):
            (old if m[1] == "-" else new).add(m[2])
    return objects, sorted(old - new), sorted(new - old)


def load_docs(text):
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    return [d for d in yaml.load_all(text, Loader=loader) if isinstance(d, dict) and d.get("kind")]


def identity(doc):
    meta = doc.get("metadata") or {}
    return doc["kind"], f"{meta.get('namespace', '')}/{meta.get('name', '')}"


def restarts(old_docs, new_docs):
    """Workloads whose pod template changes, with why each one matters."""
    old = {identity(d): d for d in old_docs}
    out = []
    for doc in new_docs:
        key = identity(doc)
        if doc["kind"] not in WORKLOADS or key not in old:
            continue
        template = (doc.get("spec") or {}).get("template")
        if template == (old[key].get("spec") or {}).get("template"):
            continue
        pod = (template or {}).get("spec") or {}
        pvc = any("persistentVolumeClaim" in v for v in pod.get("volumes") or [])
        out.append({"kind": doc["kind"], "name": key[1], "replicas": (doc.get("spec") or {}).get("replicas"),
                    "stateful": doc["kind"] in STATEFUL_KINDS or pvc})
    return out


def key_paths(data, prefix=()):
    out = set()
    if isinstance(data, dict):
        for k, v in data.items():
            path = prefix + (str(k),)
            out.add(path)
            out |= key_paths(v, path)
    return out


def dropped_keys(ours, old, new, templates):
    """Keys we set that the new chart no longer has, in defaults or in templates."""
    gone = (key_paths(ours) & key_paths(old)) - key_paths(new)
    return sorted(k for k in (".".join(p) for p in gone) if f".Values.{k}" not in templates)


def helm_objects(tree):
    """HelmReleases by name (with their directory) and HelmRepositories by name."""
    releases, repos = {}, {}
    for path in Path(tree, "k8s").rglob("*.y*ml"):
        text = path.read_text(errors="replace")
        if "kind: HelmRelease" not in text and "kind: HelmRepository" not in text:
            continue
        try:
            docs = load_docs(text)
        except yaml.YAMLError:
            continue
        for doc in docs:
            if doc["kind"] == "HelmRelease":
                releases[doc["metadata"]["name"]] = (doc, path.parent)
            elif doc["kind"] == "HelmRepository":
                repos[doc["metadata"]["name"]] = doc["spec"]["url"]
    return releases, repos


def pull_chart(chart, version, url, dest):
    ref = [f"{url.rstrip('/')}/{chart}"] if url.startswith("oci://") else [chart, "--repo", url]
    rc, out = sh(["helm", "pull", *ref, "--version", version, "--untar", "--untardir", str(dest)])
    return dest / chart if rc == 0 else None


def templates_text(chart_dir):
    return "\n".join(p.read_text(errors="replace") for p in (chart_dir / "templates").rglob("*") if p.is_file())


def check_charts(head, base):
    """A changed chart version: are our values still honoured, does our Alloy config parse?"""
    results = []
    old_rel, _ = helm_objects(base)
    new_rel, repos = helm_objects(head)
    for name, (doc, directory) in new_rel.items():
        spec = doc["spec"].get("chart", {}).get("spec", {})
        old_spec = old_rel.get(name, ({"spec": {}},))[0]["spec"].get("chart", {}).get("spec", {})
        new_v, old_v = spec.get("version"), old_spec.get("version")
        if not old_v or new_v == old_v:
            continue
        label = f"chart {name} {old_v} -> {new_v}"
        url = repos.get(spec.get("sourceRef", {}).get("name"))
        with tempfile.TemporaryDirectory() as tmp:
            old_dir = pull_chart(spec["chart"], old_v, url, Path(tmp, "old")) if url else None
            new_dir = pull_chart(spec["chart"], new_v, url, Path(tmp, "new")) if url else None
            if not old_dir or not new_dir:
                results.append(check(label, "warn", "could not pull both chart versions"))
                continue
            values = directory / "helm-values.yml"
            if values.exists():
                gone = dropped_keys(yaml.safe_load(values.read_text()) or {},
                                    yaml.safe_load((old_dir / "values.yaml").read_text()) or {},
                                    yaml.safe_load((new_dir / "values.yaml").read_text()) or {},
                                    templates_text(new_dir))
                results.append(check(f"{label}: values", "warn" if gone else "pass",
                                     f"our values set keys the new chart ignores: {', '.join(gone)}" if gone else ""))
            config = directory / "alloy.hcl"
            if config.exists():
                app = yaml.safe_load((new_dir / "Chart.yaml").read_text())["appVersion"]
                tag = app if str(app).startswith("v") else f"v{app}"
                rc, out = sh(["docker", "run", "--rm", "-v", f"{config.resolve()}:/cfg/alloy.hcl:ro",
                              f"grafana/alloy:{tag}", "validate", "/cfg/alloy.hcl"])
                results.append(check(f"alloy.hcl on Alloy {tag}", "pass" if rc == 0 else "fail",
                                     "" if rc == 0 else tail(out)))
    return results


def manifest(ref):
    """(raw bytes digest, parsed manifest) of an image, or None if it does not resolve."""
    p = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", ref],
                       capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
    if p.returncode:
        return None
    return "sha256:" + hashlib.sha256(p.stdout).hexdigest(), json.loads(p.stdout)


def image_problem(ref, inspect=manifest):
    """Why a new image is suspect, or None."""
    found = inspect(ref)
    if not found:
        return f"{ref} does not resolve"
    entries = found[1].get("manifests")
    if entries and not any((e.get("platform") or {}).get("os") == PLATFORM[0]
                           and (e.get("platform") or {}).get("architecture") == PLATFORM[1] for e in entries):
        return f"{ref} has no {'/'.join(PLATFORM)} image"
    name, _, digest = ref.partition("@")
    tag = name.rsplit(":", 1)[-1] if ":" in name.rsplit("/", 1)[-1] else ""
    # A full version should never move; floating tags (v2, latest) are meant to.
    if digest and re.fullmatch(r"v?\d+\.\d+\.\d+", tag):
        pinned = inspect(name)
        if pinned and pinned[0] != digest:
            return f"{name} now points at {pinned[0][:19]}, not the pinned digest"
    return None


def suspended(tree, flux_root, files):
    """Names of suspended Flux Kustomizations these files belong to: flate renders nothing for them."""
    hits = set()
    for path in Path(tree, flux_root).glob("*.y*ml"):
        for doc in load_docs(path.read_text(errors="replace")):
            spec = doc.get("spec") or {}
            if doc["kind"] == "Kustomization" and spec.get("suspend") and spec.get("path"):
                prefix = spec["path"].removeprefix("./").rstrip("/") + "/"
                if any(f.startswith(prefix) for f in files):
                    hits.add(doc["metadata"]["name"])
    return sorted(hits)


def check_k8s(head, base, flux_root, files):
    """Returns (checks, facts) for everything Flux would apply."""
    results, facts = [], {"objects": [], "restarts": [], "diff": ""}
    if paused := suspended(head, flux_root, files):
        results.append(check("flux suspend", "warn", f"changed but not deployed while suspended: {', '.join(paused)}"))
    rc, diff = sh(["flate", "diff", "all", "--no-progress", "--path", flux_root,
                   "--path-orig", str(Path(base, flux_root).resolve()), "-o", "diff"], head)
    if rc:
        if sh(["flate", "build", "all", "--no-progress", "--path", flux_root], base)[0] != 0:
            return results + [check("flux render", "warn", f"also fails on main: {tail(diff, 200)}")], facts
        return results + [check("flux render", "fail", tail(diff))], facts
    objects, _, new_images = parse_diff(diff)
    facts.update(objects=objects, diff=diff)
    results.append(check("flux render", "pass", f"{len(objects)} objects change"))

    rc_new, new_out = sh(["flate", "build", "all", "--no-progress", "--path", flux_root], head)
    rc_old, old_out = sh(["flate", "build", "all", "--no-progress", "--path", flux_root], base)
    if rc_new or rc_old:
        return results + [check("flux build", "warn", tail(new_out if rc_new else old_out, 200))], facts
    new_docs, old_docs = load_docs(new_out), load_docs(old_out)
    facts["restarts"] = restarts(old_docs, new_docs)

    wanted = set(objects)
    changed = [d for d in new_docs if identity(d) in wanted]
    if changed:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
            yaml.safe_dump_all(changed, f)
            f.flush()
            results.append(check_schemas(f.name))
            results.append(check_apis(f.name))
    results += check_charts(head, base)
    problems = [p for p in map(image_problem, new_images) if p]
    results.append(check(f"{len(new_images)} new images", "warn" if problems else "pass", "; ".join(problems)))
    return results, facts


def check_schemas(path):
    rc, out = sh(["kubeconform", "-summary", "-output", "json", "-ignore-missing-schemas",
                  "-schema-location", "default",
                  "-schema-location", CRD_CATALOG.format(sha=CRD_CATALOG_SHA), path])
    if rc == 0:
        return check("schemas (kubeconform)", "pass")
    try:
        bad = [r for r in json.loads(out)["resources"] if r["status"] in ("statusInvalid", "statusError")]
        detail = "; ".join(f"{r['kind']} {r['name']}: {tail(r.get('msg', ''), 160)}" for r in bad[:5])
    except (ValueError, KeyError):
        detail = tail(out)
    return check("schemas (kubeconform)", "fail", detail)


def check_apis(path):
    # ponytail: v9.99 flags every API with a removal date, whatever the cluster runs.
    rc, out = sh(["pluto", "detect", path, "--target-versions", "k8s=v9.99.0", "-o", "json"])
    if rc == 0:
        return check("deprecated APIs (pluto)", "pass")
    try:
        items = json.loads(out).get("items", [])
        detail = "; ".join(f"{i['api']['kind']} {i['name']} uses {i['api']['version']}, "
                           f"removed in {i['api'].get('removed-in') or 'a future release'}" for i in items[:5])
    except ValueError:
        detail = tail(out)
    return check("deprecated APIs (pluto)", "warn", detail)


def check_ansible(head, base):
    results = []
    for tree in (head, base):
        sh(["ansible-galaxy", "collection", "install", "-r", "requirements.yml"], tree)
    playbooks = sorted(p.relative_to(head).as_posix() for p in Path(head, "playbooks").glob("*.y*ml"))
    if Path(head, "main.yml").exists():
        playbooks.append("main.yml")
    for book in playbooks:
        results.append(differential(f"syntax {book}", ["ansible-playbook", "--syntax-check", book], head, base))
    results.append(check_lint(head, base))
    return results


def lint_findings(tree):
    rc, out = sh(["ansible-lint", "--offline", "-q", "--nocolor", "-f", "pep8"], tree)
    return rc, {re.sub(r":\d+(:\d+)?", "", line, count=1) for line in out.splitlines() if re.match(r"\S+:\d+", line)}


def check_lint(head, base):
    """Lint debt on main is not this PR's fault: only new findings count."""
    rc, new = lint_findings(head)
    if rc == 0:
        return check("ansible-lint", "pass")
    old = lint_findings(base)[1]
    if added := sorted(new - old):
        return check("ansible-lint", "warn", f"{len(added)} new: {'; '.join(added[:5])}")
    return check("ansible-lint", "pass", f"{len(old)} known findings on main, none new")


def check_tofu(head, base, files):
    """Terragrunt generates the backend, providers and shared locals, so plain tofu cannot validate a stack."""
    results = [differential("tofu fmt", ["tofu", "fmt", "-check", "-recursive", "-no-color"], head, base, "tofu")]
    os.environ["TG_TF_PATH"] = "tofu"
    os.environ.setdefault("TF_PLUGIN_CACHE_DIR", tempfile.mkdtemp())
    init = ["terragrunt", "init", "--non-interactive", "--", "-backend=false", "-input=false", "-no-color"]
    validate = ["terragrunt", "validate", "--non-interactive", "--", "-no-color"]
    for stack in sorted({"/".join(f.split("/")[:2]) for f in files if f.startswith("tofu/") and f.count("/") >= 2}):
        if not Path(head, stack, "terragrunt.hcl").is_file():
            continue
        rc, out = sh(init, Path(head, stack))
        if rc:
            results.append(differential(f"{stack} init", init, head, base, stack))
            continue
        sh(init, Path(base, stack))
        results.append(differential(f"{stack} validate", validate, head, base, stack))
    return results


def decide(types, checks, restarting, hand_run):
    """(level, reasons). Anything unproven is a reason to look, never a pass."""
    if failed := [c for c in checks if c["status"] == "fail"]:
        return "blocked", [f"{c['name']}: {c['detail']}" for c in failed]
    reasons = []
    if not types:
        reasons.append("Not a recognised Renovate update")
    elif risky := sorted(types - SAFE_UPDATES):
        reasons.append(f"{'/'.join(risky)} update: read the release notes against our config")
    reasons += [f"{c['name']}: {c['detail']}" for c in checks if c["status"] == "warn"]
    if stateful := [f"{r['kind']} {r['name']}" for r in restarting if r["stateful"]]:
        reasons.append(f"Restarts stateful workloads: {', '.join(stateful)}")
    if lone := [f"{r['kind']} {r['name']}" for r in restarting if r["replicas"] == 1 and not r["stateful"]]:
        reasons.append(f"Restarts single-replica workloads: {', '.join(lone)}")
    if hand_run:
        reasons.append(f"Takes effect only when run by hand: {', '.join(hand_run[:5])}")
    return ("review", reasons) if reasons else ("safe", ["Every check passed and only stateless workloads restart"])


TITLES = {"safe": "✅ Safe to merge", "review": "⚠️ Needs review", "blocked": "❌ Blocked"}
ICONS = {"pass": "✅", "warn": "⚠️", "fail": "❌"}


def render(level, reasons, checks, facts):
    lines = [f"### {TITLES[level]}", ""] + [f"- {r}" for r in reasons] + [""]
    if checks:
        lines += ["| Check | Result | Detail |", "|---|---|---|"]
        lines += ["| {} | {} | {} |".format(c["name"], ICONS[c["status"]], c["detail"].replace("|", "\\|").replace("\n", " "))
                  for c in checks] + [""]
    if facts["restarts"]:
        lines += ["**Pods that restart on merge:** " + ", ".join(f"{r['kind']} `{r['name']}`" for r in facts["restarts"]), ""]
    lines += ["Static checks only. They do not read release notes, test the upgrade or see live state.", ""]
    diff = facts["diff"]
    if diff:
        room = COMMENT_LIMIT - sum(len(x) + 1 for x in lines) - 200
        cut = diff if len(diff) <= room else diff[:room] + "\n... truncated, see the job log"
        lines += ["<details><summary>Rendered diff</summary>", "", "~~~~diff", cut, "~~~~", "", "</details>", ""]
    return "\n".join(lines)


def pr_info():
    event = os.environ.get("GITHUB_EVENT_PATH")
    pr = json.loads(Path(event).read_text()).get("pull_request", {}) if event else {}
    return pr.get("title", ""), pr.get("body", ""), (pr.get("user") or {}).get("login", "")


def cmd_plan(args):
    found = groups_for(changed_files(args.head, args.base))
    with open(os.environ.get("GITHUB_OUTPUT", os.devnull), "a") as f:
        for group in GROUPS:
            f.write(f"{group}={'true' if group in found else 'false'}\n")
    print("groups:", ", ".join(sorted(found)) or "none")


def cmd_run(args):
    files = changed_files(args.head, args.base)
    found = groups_for(files)
    checks, facts = [], {"objects": [], "restarts": [], "diff": ""}
    if "k8s" in found:
        results, facts = check_k8s(args.head, args.base, args.flux_root, files)
        checks += results
    if "ansible" in found:
        checks += check_ansible(args.head, args.base)
    if "tofu" in found:
        checks += check_tofu(args.head, args.base, files)
    if "nix" in found:
        checks.append(differential("nix dev shell", ["nix", "eval", "--no-write-lock-file", "--raw",
                                                     ".#devShells.x86_64-linux.default.drvPath"], args.head, args.base))
    if "poetry" in found:
        checks.append(differential("poetry lock", ["poetry", "check", "--lock"], args.head, args.base))
    if "bun" in found:
        checks.append(differential("bun lock", ["bun", "install", "--frozen-lockfile", "--ignore-scripts"], args.head, args.base))

    title, body, _ = pr_info()
    hand_run = [f for f in files if re.search(HAND_RUN, f)]
    level, reasons = decide(update_types(title, body), checks, facts["restarts"], hand_run)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    text = render(level, reasons, checks, facts)
    (out / "verdict.md").write_text(text)
    (out / "verdict.json").write_text(json.dumps({"level": level, "reasons": reasons, "checks": checks}, indent=2))
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as f:
            f.write(text)
    print(text[:4000])
    return 1 if level == "blocked" else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "run"])
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--flux-root", default="k8s")
    parser.add_argument("--out", default="verdict-out")
    args = parser.parse_args()
    return cmd_plan(args) if args.command == "plan" else cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
