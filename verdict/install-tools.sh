#!/usr/bin/env bash
# Tools for verdict.py, each pinned to a version and sha256.
set -euo pipefail

bin=${1:?usage: install-tools.sh <bin-dir> k8s|tofu}
group=${2:?usage: install-tools.sh <bin-dir> k8s|tofu}
mkdir -p "$bin"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# renovate: github-releases=home-operations/flate
FLATE_VERSION=v0.6.5
# renovate: github-releases=yannh/kubeconform
KUBECONFORM_VERSION=v0.8.0
# renovate: github-releases=FairwindsOps/pluto
PLUTO_VERSION=v5.24.5
# renovate: github-releases=gruntwork-io/terragrunt
TERRAGRUNT_VERSION=v1.1.3

fetch() { # url sha256 member
  curl -fsSL "$1" -o "$tmp/a.tgz"
  echo "$2  $tmp/a.tgz" | sha256sum -c --quiet
  tar -xzf "$tmp/a.tgz" -C "$bin" "$3"
}

case "$group" in
k8s)
  fetch "https://github.com/home-operations/flate/releases/download/$FLATE_VERSION/flate_${FLATE_VERSION#v}_linux_amd64.tar.gz" 37eb0cd91a6752340754375743aa616c263cd8367ce594abd42ee955e1ec0099 flate
  fetch "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-linux-amd64.tar.gz" 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883 kubeconform
  fetch "https://github.com/FairwindsOps/pluto/releases/download/$PLUTO_VERSION/pluto_${PLUTO_VERSION#v}_linux_amd64.tar.gz" 80076e01a320e1f4db30f5dbc927d204e61cd8abed66fa0b4644ca61cd86b39e pluto
  ;;
tofu)
  curl -fsSL "https://github.com/gruntwork-io/terragrunt/releases/download/$TERRAGRUNT_VERSION/terragrunt_linux_amd64" -o "$tmp/terragrunt"
  echo "d5da6a66741f4ee752aa3b502b57e47fd6d5c178942861b2507f14f083e7606e  $tmp/terragrunt" | sha256sum -c --quiet
  install -m 0755 "$tmp/terragrunt" "$bin/terragrunt"
  ;;
*)
  echo "unknown group: $group" >&2
  exit 1
  ;;
esac
