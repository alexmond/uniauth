#!/usr/bin/env bash
#
# Build & publish a UniAuth example image, then install/upgrade its Helm chart on a
# Kubernetes cluster and health-check the rollout.
#
# This script is deliberately GENERIC and arg-driven — it carries no cluster defaults, no
# registry, no hostname. The homelab driver supplies those from a private overlay:
#   ~/IdeaProjects/homelab-deploy/bin/deploy-app.sh uniauth
#
# Usage:
#   scripts/deploy-k8s.sh [options]
#     --example NAME          which example to deploy       (default: webapp)
#                             one of the directories under uniauth-examples/
#     --registry HOST[:PORT]  image registry                (required to push)
#     --tag TAG               image tag                     (default: project version)
#     --release NAME          Helm release name             (default: uniauth)
#     --namespace NS          target namespace              (default: uniauth)
#     --values FILE           extra Helm values file        (repeatable)
#     --pull-secret NAME      imagePullSecrets entry to set
#     --build-host TARGET     ssh target whose Docker daemon builds the image, for hosts
#                             without a real local daemon (podman shim, rootless podman)
#     --no-build              skip the build, reuse the image already in the registry
#     --no-push               build but do not publish
#     --dry-run               render the chart and stop, changing nothing
#
# Requires: kubectl + helm pointed at the target cluster. For the build, either a real
# Docker daemon (set DOCKER_HOST to use a remote one) or --no-build.
#
# NOTE: what this deploys is a DEMO carrying well-known credentials. Keep it on a trusted
# network; do not put it behind a public ingress or tunnel.

set -euo pipefail
cd "$(dirname "$0")/.."

REGISTRY=""
TAG=""
RELEASE=uniauth
NAMESPACE=uniauth
PULL_SECRET=""
BUILD_HOST=""
VALUES_ARGS=()
BUILD=1
PUBLISH=1
DRY_RUN=0

EXAMPLE=webapp

while [[ $# -gt 0 ]]; do
  case "$1" in
    --example)     EXAMPLE="$2"; shift 2 ;;
    --registry)    REGISTRY="$2"; shift 2 ;;
    --tag)         TAG="$2"; shift 2 ;;
    --release)     RELEASE="$2"; shift 2 ;;
    --namespace)   NAMESPACE="$2"; shift 2 ;;
    --values)      VALUES_ARGS+=(--values "$2"); shift 2 ;;
    --pull-secret) PULL_SECRET="$2"; shift 2 ;;
    --build-host)  BUILD_HOST="$2"; shift 2 ;;
    --no-build)    BUILD=0; shift ;;
    --no-push)     PUBLISH=0; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

MODULE="uniauth-examples/$EXAMPLE"
IMAGE_NAME="uniauth-example-$EXAMPLE"
[[ -d "$MODULE" ]] || { echo "no such example: $MODULE" >&2; exit 2; }

if [[ -z "$TAG" ]]; then
  TAG=$(./mvnw -q -Dexec.executable=echo -Dexec.args='${project.version}' \
        --non-recursive exec:exec 2>/dev/null | tail -1)
  [[ -n "$TAG" ]] || { echo "could not determine project version; pass --tag" >&2; exit 1; }
fi

if [[ -n "$REGISTRY" ]]; then
  IMAGE="$REGISTRY/$IMAGE_NAME:$TAG"
else
  IMAGE="$IMAGE_NAME:$TAG"
fi
echo "==> image: $IMAGE"

SOCKET=""
cleanup() { [[ -n "$SOCKET" ]] && rm -f "$SOCKET"; }
trap cleanup EXIT

if [[ "$BUILD" == 1 ]]; then
  if [[ -n "$BUILD_HOST" ]]; then
    # Buildpacks need a real Docker daemon; hosts without one (a podman shim, rootless
    # podman) drive a remote daemon over a forwarded socket instead. Keep the socket path
    # short — a unix socket path over ~108 chars is rejected by the kernel.
    SOCKET="/tmp/uniauth-build-$$.sock"
    echo "==> forwarding docker socket from $BUILD_HOST"
    ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 \
      -L "$SOCKET:/var/run/docker.sock" "$BUILD_HOST"
    export DOCKER_HOST="unix://$SOCKET"
  fi

  # Two steps on purpose. The example depends on the sibling starter, so that has to be
  # built and installed first (-am) — but `spring-boot:build-image` named on the command
  # line runs against every module in the reactor, and the parent and the aggregator have
  # no main class to image. So: install the siblings, then image only this module.
  # jacoco.skip as well as skipTests: the coverage gate is bound to verify, and running it
  # with no test data either fails outright or silently passes on a stale jacoco.exec left
  # by an earlier run. Gates belong in the build, not in a deploy.
  echo "==> building modules"
  ./mvnw -q -Pdefault -DskipTests -Djacoco.skip=true -pl "$MODULE" -am install

  # The build stays local (your .m2, your user); only the daemon is remote.
  echo "==> building image with buildpacks"
  ./mvnw -q -Pdefault -DskipTests -pl "$MODULE" \
    spring-boot:build-image \
    -Dspring-boot.build-image.imageName="$IMAGE"
fi

if [[ "$BUILD" == 1 && "$PUBLISH" == 1 && -n "$REGISTRY" ]]; then
  # Some registries (Zot) reject Docker-produced manifests, so the image is streamed
  # through podman, whose OCI manifest they accept. Harmless elsewhere.
  echo "==> publishing $IMAGE"
  if [[ -n "$BUILD_HOST" ]]; then
    ssh "$BUILD_HOST" "docker save $IMAGE" | podman load
    podman push "$IMAGE"
  elif command -v podman >/dev/null 2>&1; then
    docker save "$IMAGE" | podman load
    podman push "$IMAGE"
  else
    docker push "$IMAGE"
  fi
fi

HELM_ARGS=(upgrade --install "$RELEASE" deploy/helm/uniauth
           --namespace "$NAMESPACE"
           --set-string image.repository="${REGISTRY:+$REGISTRY/}$IMAGE_NAME"
           --set-string image.tag="$TAG")
[[ -n "$PULL_SECRET" ]] && HELM_ARGS+=(--set "imagePullSecrets[0].name=$PULL_SECRET")
HELM_ARGS+=("${VALUES_ARGS[@]}")

if [[ "$DRY_RUN" == 1 ]]; then
  echo "==> dry run"
  helm "${HELM_ARGS[@]}" --dry-run
  exit 0
fi

# Created up front rather than with --create-namespace, so the same call works with Helm
# implementations that lack that flag.
kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE"

echo "==> helm upgrade --install $RELEASE -n $NAMESPACE"
helm "${HELM_ARGS[@]}"

echo "==> waiting for rollout"
kubectl -n "$NAMESPACE" rollout status "deploy/$RELEASE" --timeout=180s

echo "==> OK"
kubectl -n "$NAMESPACE" get pods,svc -l "app.kubernetes.io/instance=$RELEASE"
