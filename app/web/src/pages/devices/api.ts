import { useQuery } from '@tanstack/react-query'
import { get } from '../../api/client'
import type { Candidates, Client, Device, DeviceDetail, DeviceSettings, Collector, PlatformsView, Topology } from './model'

export const usePlatforms = () => useQuery({ queryKey: ['devices', 'platforms'], queryFn: ({ signal }) => get<PlatformsView>('/api/devices/platforms', signal), staleTime: Infinity })
export const useDevices = (enabled = true) =>
  useQuery({ queryKey: ['devices', 'list'], queryFn: ({ signal }) => get<{ results: Device[] }>('/api/devices', signal), refetchInterval: 30e3, enabled })
export const useDevice = (id: number) =>
  useQuery({ queryKey: ['devices', 'one', id], queryFn: ({ signal }) => get<DeviceDetail>(`/api/devices/${id}`, signal), refetchInterval: 30e3, enabled: id > 0 })
export const useCandidates = (enabled: boolean) =>
  useQuery({ queryKey: ['devices', 'candidates'], queryFn: ({ signal }) => get<Candidates>('/api/devices/inventory-candidates', signal), enabled })
export const useClients = () => useQuery({ queryKey: ['endpoints'], queryFn: ({ signal }) => get<{ results: Client[] }>('/api/endpoints', signal), refetchInterval: 30e3 })
export const useTopology = (offline: boolean) =>
  useQuery({ queryKey: ['topology', offline], queryFn: ({ signal }) => get<Topology>(`/api/topology?offline=${offline}`, signal), refetchInterval: 60e3 })
export const useDeviceSettings = () =>
  useQuery({ queryKey: ['devices', 'settings'], queryFn: ({ signal }) => get<{ settings: DeviceSettings; collector: Collector }>('/api/settings/devices', signal) })
