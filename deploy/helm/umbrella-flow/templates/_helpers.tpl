{{/* Chart name. */}}
{{- define "flow.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Release-qualified name. */}}
{{- define "flow.fullname" -}}
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

{{- define "flow.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "flow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels; call with (dict "root" $ "role" "api"). */}}
{{- define "flow.selector" -}}
app.kubernetes.io/name: {{ include "flow.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .role }}
{{- end -}}

{{- define "flow.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "flow.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "flow.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Roles deployed: "all", or one Deployment per role. */}}
{{- define "flow.roles" -}}
{{- if eq .Values.roles.mode "split" -}}
api collector enricher detector
{{- else if eq .Values.roles.mode "all" -}}
all
{{- else -}}
{{- fail "roles.mode must be all or split" -}}
{{- end -}}
{{- end -}}

{{/* Role serving a service: (dict "root" $ "role" "api"). */}}
{{- define "flow.serviceRole" -}}
{{- if eq .root.Values.roles.mode "split" -}}{{ .role }}{{- else -}}all{{- end -}}
{{- end -}}

{{- define "flow.devName" -}}
{{- printf "%s-dev" (include "flow.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Effective connection settings (the dev services when dev.enabled). */}}
{{- define "flow.openbaoAddr" -}}
{{- if .Values.dev.enabled -}}http://{{ include "flow.devName" . }}-openbao:8200{{- else -}}{{ .Values.openbao.addr }}{{- end -}}
{{- end -}}
{{- define "flow.postgresHost" -}}
{{- if .Values.dev.enabled -}}{{ include "flow.devName" . }}-postgres{{- else -}}{{ .Values.postgres.host }}{{- end -}}
{{- end -}}
{{- define "flow.clickhouseAddr" -}}
{{- if .Values.dev.enabled -}}{{ include "flow.devName" . }}-clickhouse:9000{{- else -}}{{ .Values.clickhouse.addr }}{{- end -}}
{{- end -}}
{{- define "flow.natsURL" -}}
{{- if .Values.dev.enabled -}}nats://{{ include "flow.devName" . }}-nats:4222{{- else -}}{{ .Values.nats.url }}{{- end -}}
{{- end -}}

{{/* Secret holding the OpenBao credential files. */}}
{{- define "flow.openbaoSecret" -}}
{{- if .Values.dev.enabled -}}{{ include "flow.devName" . }}{{- else -}}{{ .Values.openbao.existingSecret }}{{- end -}}
{{- end -}}

{{/* Does a split-mode pod of a non-API role get flow.json? */}}
{{- define "flow.sharedData" -}}
{{- if or .Values.persistence.existingClaim (has "ReadWriteMany" .Values.persistence.accessModes) -}}true{{- end -}}
{{- end -}}

{{- define "flow.claimName" -}}
{{- default (printf "%s-data" (include "flow.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}
