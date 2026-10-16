import { useMemo, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { RotateCcw } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { put } from '../../api/client'
import { EChart, chartTheme, FONT } from '../../charts/EChart'
import { errorText, useT } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Loading, Switch } from '../../ui/ui'
import { useTheme } from '../../theme'
import { useTopology } from './api'
import { graphOf, NODE_COLORS, positionsOf, type Topology } from './model'
import { devicesStrings } from './strings'
import './devices.css'

echarts.use([GraphChart])

// Network → Map: the network map (ECharts graph). Devices can be dragged; their positions are
// stored for everyone (PUT /api/topology/positions).

export default function MapPage() {
  const t = useT(devicesStrings)
  const { can } = useSession()
  const [clients, setClients] = useState(true)
  const [offline, setOffline] = useState(false)
  const [labels, setLabels] = useState(true)
  const q = useTopology(offline)
  const qc = useQueryClient()
  const edit = can('devices:edit')
  const reset = useMutation({
    mutationFn: (topo: Topology) => put('/api/topology/positions', Object.fromEntries(topo.nodes.filter((n) => n.type === 'device').map((n) => [n.id, null]))),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['topology'] }),
    onError: (e) => notify('error', errorText(t, e).message),
  })
  const s = q.data?.stats
  return (
    <Page
      id="map"
      wide
      subtitle={t('map.sub')}
      actions={
        edit &&
        q.data && (
          <Button onClick={() => reset.mutate(q.data)} busy={reset.isPending}>
            <RotateCcw size={15} /> {t('map.reset')}
          </Button>
        )
      }
    >
      <section className="card toolbar-card dev-toolbar">
        <Switch checked={clients} onChange={setClients} label={t('map.clients')} />
        <Switch checked={offline} onChange={setOffline} label={t('map.offline')} disabled={!clients} />
        <Switch checked={labels} onChange={setLabels} label={t('map.labels')} />
        {s && <span className="muted map-stats">{t('map.stats', { devices: s.devices, children: s.children, neighbors: s.neighbors, endpoints: s.endpoints })}</span>}
      </section>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      <section className="card map-card">
        {q.isPending ? <Loading /> : q.data && q.data.nodes.length > 0 ? <Graph topo={q.data} clients={clients} labels={labels} editable={edit} /> : <p className="muted empty-pad">{t('map.empty')}</p>}
        <div className="map-legend">
          {(
            [
              ['device', NODE_COLORS.up],
              ['child', NODE_COLORS.up],
              ['neighbor', NODE_COLORS.neighbor],
              ['endpoint', NODE_COLORS.online],
            ] as const
          ).map(([k, c]) => (
            <span key={k} className="map-legend-item">
              <span className={`map-dot map-dot-${k}`} style={{ background: c }} /> {t(`map.legend.${k}`)}
            </span>
          ))}
        </div>
      </section>
    </Page>
  )
}

function Graph({ topo, clients, labels, editable }: { topo: Topology; clients: boolean; labels: boolean; editable: boolean }) {
  const t = useT(devicesStrings)
  const nav = useNavigate()
  const { theme } = useTheme()
  const chart = useRef<echarts.ECharts | null>(null)
  const save = useMutation({
    mutationFn: (pos: Record<string, [number, number]>) => put('/api/topology/positions', pos),
    onSuccess: () => notify('ok', t('map.saved')),
    onError: (e) => notify('error', errorText(t, e).message),
  })
  const option = useMemo(() => {
    const th = chartTheme()
    const { nodes, links } = graphOf(topo, { clients, labels })
    const byId = new Map(topo.nodes.map((n) => [n.id, n]))
    return {
      textStyle: { fontFamily: FONT },
      tooltip: {
        confine: true,
        formatter: (p: { dataType: string; data: { id?: string; value?: string; source?: string; target?: string } }) => {
          if (p.dataType === 'edge') return p.data.value || ''
          const n = byId.get(p.data.id ?? '')
          if (!n) return ''
          const rest = [n.ip, n.model, n.vendor, n.ssid, n.error].filter(Boolean).map((x) => escapeHTML(String(x)))
          return [`<b>${escapeHTML(n.label)}</b>`, ...rest].join('<br>')
        },
      },
      series: [
        {
          type: 'graph',
          layout: 'force',
          roam: true,
          draggable: editable,
          force: { repulsion: 220, edgeLength: [60, 160], gravity: 0.08, layoutAnimation: true },
          label: { position: 'bottom', color: th.text, fontSize: 11 },
          lineStyle: { curveness: 0.05 },
          emphasis: { focus: 'adjacency', lineStyle: { width: 3 } },
          data: nodes,
          links,
        },
      ],
    }
    // theme: re-read the tokens when it changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topo, clients, labels, editable, theme])
  const events = useMemo(
    () => ({
      dblclick: (p: unknown) => {
        const d = (p as { dataType?: string; data?: { id?: string } }).data
        const n = topo.nodes.find((x) => x.id === d?.id)
        if (n?.device_id) nav(`/devices/${n.device_id}`)
      },
      mouseup: (p: unknown) => {
        const e = p as { dataType?: string; data?: { id?: string }; dataIndex?: number }
        if (!editable || e.dataType !== 'node' || !e.data?.id?.startsWith('dev:') || !chart.current) return
        // The laid-out position of the dragged node (ECharts keeps it in the series model).
        const model = (chart.current as unknown as { getModel(): { getSeriesByIndex(i: number): { getData(): { getItemLayout(i: number): [number, number] } } } }).getModel()
        const xy = model.getSeriesByIndex(0).getData().getItemLayout(e.dataIndex ?? 0)
        if (xy) save.mutate(positionsOf([{ id: e.data.id, x: xy[0], y: xy[1] }]))
      },
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [topo, editable],
  )
  return <EChart option={option} height={620} events={events} onReady={(c) => (chart.current = c)} />
}

function escapeHTML(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c)
}
