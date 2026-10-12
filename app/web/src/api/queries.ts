import { useQuery } from '@tanstack/react-query'
import { get } from './client'
import type { Exporter, Me, Schema } from './types'
import type { SetupInfo } from '../pages/setup/types'

export const useMe = () => useQuery({ queryKey: ['me'], queryFn: ({ signal }) => get<Me>('/api/auth/me', signal), retry: false, staleTime: 60e3 })
export const useSetupState = () => useQuery({ queryKey: ['setup'], queryFn: ({ signal }) => get<SetupInfo>('/api/setup', signal), retry: 1, staleTime: Infinity, retryOnMount: false, refetchOnMount: false })
export const useSchema = () => useQuery({ queryKey: ['schema'], queryFn: ({ signal }) => get<Schema>('/api/schema', signal), staleTime: Infinity })
export const useExporters = () =>
  useQuery({ queryKey: ['exporters'], queryFn: ({ signal }) => get<{ results: Exporter[] }>('/api/exporters', signal), refetchInterval: 30e3 })
