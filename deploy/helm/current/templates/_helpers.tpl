{{/* Chart name. */}}
{{- define "current.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Release-qualified name. */}}
{{- define "current.fullname" -}}
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

{{- define "current.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "current.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels; call with (dict "root" $ "role" "api"). */}}
{{- define "current.selector" -}}
app.kubernetes.io/name: {{ include "current.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .role }}
{{- end -}}

{{- define "current.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "current.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "current.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Roles deployed: "all", or one Deployment per role. */}}
{{- define "current.roles" -}}
{{- if eq .Values.roles.mode "split" -}}
api collector enricher detector
{{- else if eq .Values.roles.mode "all" -}}
all
{{- else -}}
{{- fail "roles.mode must be all or split" -}}
{{- end -}}
{{- end -}}

{{/* Role serving a service: (dict "root" $ "role" "api"). */}}
{{- define "current.serviceRole" -}}
{{- if eq .root.Values.roles.mode "split" -}}{{ .role }}{{- else -}}all{{- end -}}
{{- end -}}

{{- define "current.devName" -}}
{{- printf "%s-dev" (include "current.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Effective connection settings (the dev services when dev.enabled). */}}
{{- define "current.openbaoAddr" -}}
{{- if .Values.dev.enabled -}}http://{{ include "current.devName" . }}-openbao:8200{{- else -}}{{ .Values.openbao.addr }}{{- end -}}
{{- end -}}
{{- define "current.postgresHost" -}}
{{- if .Values.dev.enabled -}}{{ include "current.devName" . }}-postgres{{- else -}}{{ .Values.postgres.host }}{{- end -}}
{{- end -}}
{{- define "current.clickhouseAddr" -}}
{{- if .Values.dev.enabled -}}{{ include "current.devName" . }}-clickhouse:9000{{- else -}}{{ .Values.clickhouse.addr }}{{- end -}}
{{- end -}}
{{- define "current.natsURL" -}}
{{- if .Values.dev.enabled -}}nats://{{ include "current.devName" . }}-nats:4222{{- else -}}{{ .Values.nats.url }}{{- end -}}
{{- end -}}

{{/* Secret holding the OpenBao credential files. */}}
{{- define "current.openbaoSecret" -}}
{{- if .Values.dev.enabled -}}{{ include "current.devName" . }}{{- else -}}{{ .Values.openbao.existingSecret }}{{- end -}}
{{- end -}}

{{/* Does a split-mode pod of a non-API role get flow.json? */}}
{{- define "current.sharedData" -}}
{{- if or .Values.persistence.existingClaim (has "ReadWriteMany" .Values.persistence.accessModes) -}}true{{- end -}}
{{- end -}}

{{- define "current.claimName" -}}
{{- default (printf "%s-data" (include "current.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}
