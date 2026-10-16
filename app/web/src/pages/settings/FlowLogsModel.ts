// Cloud flow log settings (docs/api.md, "Cloud flow logs"): per-provider ingest endpoints with
// write-only tokens in OpenBao, and the snippets that configure the cloud side.

export const PROVIDERS = ['aws', 'azure', 'gcp'] as const
export type Provider = (typeof PROVIDERS)[number]

export type ProviderView = { enabled: boolean; token_set: boolean; endpoint: string; url?: string }
export type FlowLogsView = { available: boolean; public_url?: string } & Record<Provider, ProviderView>

export type ProviderDraft = { enabled: boolean; token: string; remove: boolean }

export const MIN_TOKEN = 16

// ingestURL is the absolute address the cloud side posts to: the server's (from the public URL of
// the general settings), else the console's own origin.
export function ingestURL(v: ProviderView, origin: string): string {
  return v.url || origin.replace(/\/$/, '') + v.endpoint
}

// providerBody is the PUT member of one provider: the token only when entered or removed.
export function providerBody(d: ProviderDraft): { enabled: boolean; token?: string } {
  if (d.remove) return { enabled: false, token: '' }
  return d.token ? { enabled: d.enabled, token: d.token } : { enabled: d.enabled }
}

// problem returns the message key of what blocks saving a provider, or null.
export function problem(v: ProviderView, d: ProviderDraft): string | null {
  if (d.remove) return null
  if (d.token && d.token.length < MIN_TOKEN) return 'fl.err.short'
  if (d.enabled && !d.token && !v.token_set) return 'fl.err.token'
  return null
}

// randomToken makes a 32-character URL-safe token for a provider.
export function randomToken(): string {
  const b = new Uint8Array(24)
  crypto.getRandomValues(b)
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const TOKEN = '<token>'

// snippet is the cloud-side setup for a provider, with the ingest URL filled in.
export function snippet(p: Provider, url: string): string {
  switch (p) {
    case 'aws':
      return [
        '# VPC Flow Logs → Kinesis Data Firehose → HTTP endpoint (Current)',
        'aws firehose create-delivery-stream --delivery-stream-name umbrella-flow \\',
        '  --delivery-stream-type DirectPut \\',
        `  --http-endpoint-destination-configuration '{`,
        `    "EndpointConfiguration": {"Url": "${url}", "Name": "Current", "AccessKey": "${TOKEN}"},`,
        '    "RequestConfiguration": {"ContentEncoding": "GZIP"},',
        '    "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},',
        '    "S3BackupMode": "FailedDataOnly",',
        '    "S3Configuration": {"RoleARN": "arn:aws:iam::<account>:role/<firehose-role>", "BucketARN": "arn:aws:s3:::<backup-bucket>"},',
        '    "RoleARN": "arn:aws:iam::<account>:role/<firehose-role>"',
        "  }'",
        '',
        'aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-<id> --traffic-type ALL \\',
        '  --log-destination-type kinesis-data-firehose \\',
        '  --log-destination arn:aws:firehose:<region>:<account>:deliverystream/umbrella-flow \\',
        '  --max-aggregation-interval 60',
        '# Custom formats: add ?fields=${version}%20${srcaddr}… to the URL (or keep the default v2 format).',
      ].join('\n')
    case 'azure':
      return [
        '# NSG / VNet flow logs are written to a storage account. Forward each new blob',
        '# (Event Grid "BlobCreated" → Azure Function) to Current as is:',
        '',
        '// function.js (Node.js, blob trigger on insights-logs-flowlogflowevent / insights-logs-networksecuritygroupflowevent)',
        'module.exports = async function (context, blob) {',
        `  const res = await fetch('${url}', {`,
        "    method: 'POST',",
        `    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ${TOKEN}' },`,
        '    body: blob, // {"records": [...]} as written by Azure',
        '  })',
        "  if (!res.ok) throw new Error('Current answered ' + res.status) // retried by the runtime",
        '}',
      ].join('\n')
    case 'gcp': {
      const sep = url.includes('?') ? '&' : '?'
      return [
        '# VPC Flow Logs → Log Router sink → Pub/Sub topic → push subscription (Current)',
        'gcloud pubsub topics create umbrella-flow',
        'gcloud logging sinks create umbrella-flow pubsub.googleapis.com/projects/<project>/topics/umbrella-flow \\',
        '  --log-filter=\'logName:"logs/compute.googleapis.com%2Fvpc_flows"\'',
        '# grant the sink writer identity roles/pubsub.publisher on the topic, then:',
        'gcloud pubsub subscriptions create umbrella-flow-push --topic umbrella-flow \\',
        `  --push-endpoint='${url}${sep}token=${TOKEN}' --ack-deadline 60`,
        '# Pub/Sub push cannot send a static header, so the token is a URL parameter.',
      ].join('\n')
    }
  }
}
