# uniauth chart

Deploys the **example web app** (`uniauth-examples/webapp`), not the library. UniAuth itself
is a Spring Boot starter — a jar deploys nothing.

> **This is a demo.** The example ships well-known credentials in its configuration on
> purpose (`alice/s3cret`, `breakglass/local-only`, `bob/bobspassword`), so anything that can
> reach it can sign in. Keep it on a trusted network. Do not put it behind a public ingress
> or tunnel without replacing those credentials with bcrypt values from a Secret first.

## Install

```sh
scripts/deploy-k8s.sh --registry <registry> --values my-values.yaml
```

or by hand, against an image you have already published:

```sh
helm upgrade --install uniauth deploy/helm/uniauth -n uniauth --create-namespace \
  --set-string image.repository=<registry>/uniauth-example-webapp \
  --set-string image.tag=<tag> \
  --values my-values.yaml
```

## Values worth knowing

| Key | Default | Notes |
|---|---|---|
| `ingress.host` | *(none)* | **Required** when `ingress.enabled`. The chart ships no default and fails rather than guessing — a fallback would publish the app on a hostname nobody expects. |
| `managementPort` | `9090` | Actuator's container port. Never routed by the ingress, so `/actuator/**` 404s from outside. Set equal to `service.port` to fold it back onto the app port. |
| `managementDiscoverable` | `false` | Adds the `bootapp` label and `management.*` annotations Spring Boot Admin discovers on, plus the Service port. |
| `existingSecret` | `""` | Name of a Secret injected via `envFrom`. The chart does **not** manage it — create it out of band so values never pass through Helm. |
| `profiles` | `k8s` | The profile that moves actuator to the management port. |

## Requirements the app must meet

The image needs `spring-boot-starter-actuator` and the `k8s` profile, or no management port
opens, the probes have nothing to talk to, and the pod never goes Ready. Both are already
wired into `uniauth-examples/webapp`.

## Probes

Readiness and liveness target the **management** port whenever it differs from the service
port. Point them at `http` and the pod will never go Ready once the `k8s` profile has moved
actuator off 8080.

`/actuator/**` is permitted in the `k8s` profile via `uniauth.public-paths`. That is
deliberate: probes, Prometheus and SBA send no credentials, and requiring the app's own auth
there would 401 exactly the callers the endpoint exists for. It is safe because the
management port is cluster-internal and never on the ingress.
