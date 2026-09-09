{{/*
Expand the chart name.
*/}}
{{- define "dwara.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully-qualified app name (chart-name[-release] when overridden).
*/}}
{{- define "dwara.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "dwara.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart name + version label.
*/}}
{{- define "dwara.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every object the chart renders.
*/}}
{{- define "dwara.labels" -}}
helm.sh/chart: {{ include "dwara.chart" . }}
app.kubernetes.io/name: {{ include "dwara.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dwara
{{- end -}}

{{/*
Selector labels (stable across upgrades).
*/}}
{{- define "dwara.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dwara.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{/*
The namespace to install into.
*/}}
{{- define "dwara.namespace" -}}
{{- if .Values.namespace.name -}}
{{- .Values.namespace.name -}}
{{- else -}}
{{- .Release.Namespace -}}
{{- end -}}
{{- end -}}
