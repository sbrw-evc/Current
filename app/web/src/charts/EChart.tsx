import { useEffect, useRef } from 'react'
import * as echarts from 'echarts/core'
import { LineChart, SankeyChart, BarChart } from 'echarts/charts'
import { AxisPointerComponent, DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent, TooltipComponent, BrushComponent, ToolboxComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { EChartsCoreOption } from 'echarts/core'

echarts.use([LineChart, SankeyChart, BarChart, GridComponent, TooltipComponent, LegendComponent, AxisPointerComponent, MarkLineComponent, DataZoomComponent, BrushComponent, ToolboxComponent, CanvasRenderer])

export type ChartEvents = Record<string, (params: unknown) => void>

// EChart: a small wrapper around an ECharts instance. The option is replaced as a whole on every
// change (notMerge), the chart follows the size of its box, and the instance is disposed on unmount.
export function EChart({ option, height, className, events, onReady }: { option: EChartsCoreOption; height: number | string; className?: string; events?: ChartEvents; onReady?: (c: echarts.ECharts) => void }) {
  const box = useRef<HTMLDivElement>(null)
  const chart = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    const el = box.current
    if (!el) return
    const c = echarts.init(el, undefined, { renderer: 'canvas' })
    chart.current = c
    onReady?.(c)
    const ro = new ResizeObserver(() => c.resize())
    ro.observe(el)
    return () => {
      ro.disconnect()
      c.dispose()
      chart.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    chart.current?.setOption(option, { notMerge: true, lazyUpdate: true })
  }, [option])

  useEffect(() => {
    const c = chart.current
    if (!c || !events) return
    for (const [name, fn] of Object.entries(events)) c.on(name, fn)
    return () => {
      for (const [name, fn] of Object.entries(events)) c.off(name, fn)
    }
  }, [events])

  return <div ref={box} className={className} style={{ width: '100%', height }} data-native-scroll />
}

// chartTheme reads the theme tokens, so the charts use the same ink and lines as the page.
export function chartTheme() {
  const s = getComputedStyle(document.documentElement)
  const v = (name: string) => s.getPropertyValue(name).trim()
  return {
    dark: document.documentElement.dataset.theme === 'dark',
    text: v('--text'),
    muted: v('--muted'),
    border: v('--border'),
    grid: v('--chart-grid') || v('--border'),
    surface: v('--surface'),
    accent: v('--accent'),
  }
}

export const FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
