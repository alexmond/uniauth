{{/* Chart name, overridable. */}}
{{- define "uniauth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified release name. */}}
{{- define "uniauth.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "uniauth.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "uniauth.labels" -}}
helm.sh/chart: {{ include "uniauth.chart" . }}
{{ include "uniauth.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "uniauth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "uniauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "uniauth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "uniauth.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference. A numeric tag (a date like 20260815) is parsed from YAML as a float and
would render as 2.0260815e+07, which is not a valid image name — coerce it back first.
*/}}
{{- define "uniauth.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if kindIs "float64" $tag -}}
{{- $tag = printf "%.0f" $tag -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Ingress host. Deliberately fails rather than defaulting: the chart ships no domain, so a
missing host means the overrides file forgot one, and a silent fallback would publish the
app on a hostname nobody expects.
*/}}
{{- define "uniauth.ingressHost" -}}
{{- required "ingress.host is required when ingress.enabled is true — set it in your values file" .Values.ingress.host -}}
{{- end -}}
