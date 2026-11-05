#!/usr/bin/env python3
"""Checks for the parts that decide the verdict. Run: python3 test_verdict.py"""
import tempfile
from pathlib import Path

import verdict as v

RENOVATE = "This PR contains the following updates:\n\n"


def test_update_types():
    assert v.update_types("x", RENOVATE + "| Package | Type | Update | Change |\n|---|---|---|---|\n| a | Kustomization | pinDigest | -> `c67a` |\n") == {"pinDigest"}
    assert v.update_types("x", RENOVATE + "| Package | Update | Change | Pending |\n|---|---|---|---|\n| a | patch | `1` | `2` |\n\n---\n| not | the | table |\n") == {"patch"}
    # Grouped PRs have no Update column.
    grouped = "| Package | Change | Age |\n|---|---|---|\n| a | `1.19.2` → `1.19.9` | x |\n| b | `==1.43.111` → `==1.43.116` | x |\n"
    assert v.update_types("Update non-major", RENOVATE + grouped) == {"patch"}
    assert v.update_types("x", RENOVATE + "| Package | Change |\n|---|---|\n| a | `v2.9.5` → `v3.0.0` |\n") == {"major"}
    assert v.update_types("chore(deps): lock file maintenance", "") == {"lockFileMaintenance"}
    assert v.update_types("a human PR", "no table here") == set()


def test_parse_diff():
    diff = """--- Deployment windmill/app
+++ Deployment windmill/app
@@ -1,2 +1,2 @@
-        image: ghcr.io/a/b:1.0
+        image: ghcr.io/a/b:1.1
--- PodDisruptionBudget windmill/app
+++ PodDisruptionBudget windmill/app
@@ -1 +1 @@
-  - image: same:1
+  - image: same:1
"""
    objects, old, new = v.parse_diff(diff)
    assert objects == [("Deployment", "windmill/app"), ("PodDisruptionBudget", "windmill/app")]
    assert (old, new) == (["ghcr.io/a/b:1.0"], ["ghcr.io/a/b:1.1"])


def pod(image, **spec):
    return {"template": {"spec": {"containers": [{"image": image}], **spec}}}


def test_restarts():
    old = [{"kind": "Deployment", "metadata": {"namespace": "a", "name": "web"}, "spec": {"replicas": 2, **pod("x:1")}},
           {"kind": "Deployment", "metadata": {"namespace": "a", "name": "same"}, "spec": pod("x:1")},
           {"kind": "Deployment", "metadata": {"namespace": "a", "name": "disk"}, "spec": pod("x:1")},
           {"kind": "StatefulSet", "metadata": {"namespace": "a", "name": "redis"}, "spec": pod("x:1")}]
    pvc = [{"name": "d", "persistentVolumeClaim": {"claimName": "c"}}]
    new = [{"kind": "Deployment", "metadata": {"namespace": "a", "name": "web"}, "spec": {"replicas": 2, **pod("x:2")}},
           {"kind": "Deployment", "metadata": {"namespace": "a", "name": "same"}, "spec": pod("x:1")},
           {"kind": "Deployment", "metadata": {"namespace": "a", "name": "disk"}, "spec": pod("x:2", volumes=pvc)},
           {"kind": "StatefulSet", "metadata": {"namespace": "a", "name": "redis"}, "spec": pod("x:2")},
           {"kind": "Deployment", "metadata": {"namespace": "a", "name": "brand-new"}, "spec": pod("x:1")}]
    got = {r["name"]: r["stateful"] for r in v.restarts(old, new)}
    assert got == {"a/web": False, "a/disk": True, "a/redis": True}


def test_dropped_keys():
    ours = {"a": {"gone": 1, "kept": 2, "custom": 3}, "still-read": False}
    old = {"a": {"gone": 0, "kept": 0}, "still-read": True}
    new = {"a": {"kept": 0}}
    assert v.dropped_keys(ours, old, new, "{{ .Values.still-read }}") == ["a.gone"]


def test_image_problem():
    index = {"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}}]}
    arm = {"manifests": [{"platform": {"os": "linux", "architecture": "arm64"}}]}
    assert v.image_problem("a/b:1.2.3", lambda r: None) == "a/b:1.2.3 does not resolve"
    assert "no linux/amd64" in v.image_problem("a/b:1.2.3", lambda r: ("sha256:x", arm))
    assert v.image_problem("a/b:1.2.3", lambda r: ("sha256:x", index)) is None
    moved = v.image_problem("a/b:1.2.3@sha256:old", lambda r: ("sha256:old" if "@" in r else "sha256:new", index))
    assert "now points at" in moved
    # Floating tags are meant to move.
    assert v.image_problem("a/b:v2@sha256:old", lambda r: ("sha256:old" if "@" in r else "sha256:new", index)) is None


def test_decide():
    ok = v.check("render", "pass")
    calm = {"kind": "Deployment", "name": "a/web", "replicas": 2, "stateful": False}
    lone = {"kind": "Deployment", "name": "a/web", "replicas": 1, "stateful": False}
    db = {"kind": "StatefulSet", "name": "a/redis", "replicas": 1, "stateful": True}
    assert v.decide({"digest"}, [ok], [calm], [])[0] == "safe"
    assert v.decide({"digest"}, [ok], [lone], [])[0] == "review"
    assert v.decide({"digest"}, [ok], [db], [])[0] == "review"
    assert v.decide({"patch"}, [ok], [], ["scripts/install-cilium.sh"])[0] == "review"
    assert v.decide({"minor"}, [ok], [], [])[0] == "review"
    assert v.decide({"major", "patch"}, [ok], [], [])[0] == "review"
    assert v.decide(set(), [ok], [], [])[0] == "review"
    assert v.decide({"digest"}, [v.check("x", "warn", "hm")], [], [])[0] == "review"
    assert v.decide({"digest"}, [v.check("x", "fail", "no")], [], [])[0] == "blocked"


def test_render_stays_under_the_comment_limit():
    text = v.render("review", ["r"], [v.check("a|b", "warn", "x")], {"objects": [], "restarts": [], "diff": "d" * 200_000})
    assert len(text) < 65_536 and "truncated" in text and "a|b" in text


def test_suspended():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "flux").mkdir()
        Path(tmp, "flux/a.yml").write_text("---\nkind: Kustomization\nmetadata: {name: paused}\nspec: {suspend: true, path: ./k8s/a}\n")
        Path(tmp, "flux/b.yml").write_text("kind: Kustomization\nmetadata: {name: live}\nspec: {path: ./k8s/b}\n")
        assert v.suspended(tmp, "flux", ["k8s/a/x.yml", "k8s/b/x.yml", "k8s/ab/x.yml"]) == ["paused"]
        assert v.suspended(tmp, "flux", ["k8s/b/x.yml"]) == []


def test_groups():
    files = ["k8s/blueprints/a/b.yml", "tofu/dns-x/versions.tf", "flake.lock", "requirements.yml", "README.md"]
    assert v.groups_for(files) == {"k8s", "tofu", "nix", "ansible"}
    assert v.groups_for(["README.md"]) == set()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
