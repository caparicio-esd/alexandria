{{/*
Names.

Kubernetes caps most names at 63 characters, so every one of these truncates.
The trailing "-" trim matters: truncation can land on a hyphen, and a name that
ends in one is refused by the API server rather than silently accepted.
*/}}

{{- define "alexandria.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "alexandria.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "alexandria.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Labels.

selectorLabels is the subset that goes in a Deployment's selector, and it is
immutable once applied — the two are separate because the full set carries the
chart and app versions, which change on every upgrade and would make the
selector unpatchable.
*/}}

{{- define "alexandria.labels" -}}
helm.sh/chart: {{ include "alexandria.chart" . }}
{{ include "alexandria.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "alexandria.selectorLabels" -}}
app.kubernetes.io/name: {{ include "alexandria.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "alexandria.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "alexandria.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Addresses.

Every one of these is derived from a single host value rather than restated, so
a domain change is one edit. The OAuth redirect URI in particular has to match
what is registered in the identity provider to the character.
*/}}

{{- define "alexandria.scheme" -}}
{{- if .Values.ingress.tls.enabled }}https{{ else }}http{{ end }}
{{- end }}

{{- define "alexandria.externalURL" -}}
{{- printf "%s://%s" (include "alexandria.scheme" .) (required "ingress.host is required" .Values.ingress.host) }}
{{- end }}

{{- define "alexandria.issuer" -}}
{{- if .Values.auth.issuer }}
{{- .Values.auth.issuer }}
{{- else }}
{{- printf "%s://%s" (include "alexandria.scheme" .) (required "auth.host or auth.issuer is required" .Values.auth.host) }}
{{- end }}
{{- end }}

{{/*
Where the node reaches the identity provider from inside the cluster, when that
differs from the address the browser uses. With the bundled Zitadel subchart it
always differs, and going out through the ingress to come back in — hairpin —
depends on the load balancer supporting it, which not all do.
*/}}
{{- define "alexandria.internalIssuer" -}}
{{- if .Values.auth.internalIssuer }}
{{- .Values.auth.internalIssuer }}
{{- else if .Values.zitadel.enabled }}
{{- printf "http://%s-zitadel:8080" .Release.Name }}
{{- end }}
{{- end }}

{{/*
The database host. The bundled subchart's service name is fixed by the
convention Bitnami's chart follows; an external database names its own.
*/}}
{{- define "alexandria.databaseHost" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- required "database.host is required when postgresql.enabled is false" .Values.database.host }}
{{- end }}
{{- end }}

{{/*
The Secret holding the credentials. Either this chart renders one from values,
or the deployment points at one it manages itself — with a sealed secret, an
external-secrets operator, or by hand — and the chart never sees the values.
*/}}
{{- define "alexandria.secretName" -}}
{{- default (printf "%s-secrets" (include "alexandria.fullname" .)) .Values.existingSecret }}
{{- end }}
