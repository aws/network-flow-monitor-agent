{{/*
Get the current recommended 'aws-network-flow-monitor-agent' image for a given k8s version
*/}}
{{- define "aws-network-flow-monitor-agent.image" -}}
{{- if .Values.image.override -}}
{{- .Values.image.override -}}
{{- else -}}
{{- $imageDomain := "" -}}
{{- if .Values.image.containerRegistry -}}
{{- $imageDomain = .Values.image.containerRegistry -}}
{{- end -}}
{{- if not $imageDomain -}}
{{- fail "Undefined Image Container Registry" -}}
{{- end -}}
{{- printf "%s/%s:%s" $imageDomain .Values.image.name .Values.image.tag -}}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "aws-network-flow-monitor-agent.labels" -}}
{{ include "aws-network-flow-monitor-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: EKS
{{ include "aws-network-flow-monitor-agent.additionalLabels" . }}
{{- end }}

{{- define "aws-network-flow-monitor-agent.additionalLabels" -}}
{{- if .Values.additionalLabels }}
{{- tpl (.Values.additionalLabels | toYaml) . }}
{{- end }}
{{- end }}

{{/*
Expand the name of the chart.
*/}}
{{- define "aws-network-flow-monitor-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "aws-network-flow-monitor-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aws-network-flow-monitor-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}