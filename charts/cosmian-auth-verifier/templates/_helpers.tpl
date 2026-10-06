{{/*
Expand the name of the chart.
*/}}
{{- define "cosmian-auth-verifier.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to
this (by the DNS naming spec).
*/}}
{{- define "cosmian-auth-verifier.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cosmian-auth-verifier.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cosmian-auth-verifier.labels" -}}
helm.sh/chart: {{ include "cosmian-auth-verifier.chart" . }}
{{ include "cosmian-auth-verifier.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cosmian-auth-verifier.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cosmian-auth-verifier.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "cosmian-auth-verifier.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cosmian-auth-verifier.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the image tag: the chart appVersion by default, with the "-saml" suffix
of the SAML image variant when saml.enabled is true. An explicit image.tag is
used verbatim.
*/}}
{{- define "cosmian-auth-verifier.imageTag" -}}
{{- if .Values.image.tag }}
{{- .Values.image.tag }}
{{- else if .Values.saml.enabled }}
{{- printf "%s-saml" .Chart.AppVersion }}
{{- else }}
{{- .Chart.AppVersion }}
{{- end }}
{{- end }}

{{/*
URL scheme served by the container.
*/}}
{{- define "cosmian-auth-verifier.scheme" -}}
{{- if .Values.authVerifier.tls.enabled }}https{{ else }}http{{ end }}
{{- end }}

{{/*
Resolve the PVC name used by the sqlite backend.
*/}}
{{- define "cosmian-auth-verifier.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "cosmian-auth-verifier.fullname" . }}
{{- end }}
{{- end }}

{{/*
Name of the chart-managed Secret holding database connection URLs.
*/}}
{{- define "cosmian-auth-verifier.dbSecretName" -}}
{{- printf "%s-db" (include "cosmian-auth-verifier.fullname" .) }}
{{- end }}
