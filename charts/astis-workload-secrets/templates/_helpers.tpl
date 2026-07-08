{{- define "astis-workload-secrets.name" -}}
{{- default .Release.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "astis-workload-secrets.serviceAccountName" -}}
{{- default (include "astis-workload-secrets.name" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "astis-workload-secrets.namespace" -}}
{{- if .Values.namespace.create -}}
{{- .Values.namespace.name -}}
{{- else -}}
{{- default .Release.Namespace .Values.namespace.name -}}
{{- end -}}
{{- end -}}

{{- define "astis-workload-secrets.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}

{{- define "astis-workload-secrets.labels" -}}
app.kubernetes.io/name: {{ include "astis-workload-secrets.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
