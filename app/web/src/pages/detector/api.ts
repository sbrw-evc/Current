import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { get, post, put } from '../../api/client'
import type { DetectorStatus, Rule, RulesView } from './model'

// The detector API (docs/api.md "Detector").

export const useRules = (enabled = true) => useQuery({ queryKey: ['detector', 'rules'], queryFn: ({ signal }) => get<RulesView>('/api/detector/rules', signal), enabled })

export const useDefaultRules = (enabled = true) =>
  useQuery({ queryKey: ['detector', 'defaults'], queryFn: ({ signal }) => get<RulesView>('/api/detector/rules/defaults', signal), staleTime: Infinity, enabled })

export const useDetectorStatus = (refetch = 10e3, enabled = true) =>
  useQuery({ queryKey: ['detector', 'status'], queryFn: ({ signal }) => get<DetectorStatus>('/api/detector/status', signal), refetchInterval: refetch, enabled })

// useSaveRules PUTs the whole list (the server checks every rule) and refreshes the caches.
export function useSaveRules() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (rules: Rule[]) => put<RulesView>('/api/detector/rules', { rules }),
    onSuccess: (v) => {
      qc.setQueryData(['detector', 'rules'], v)
      void qc.invalidateQueries({ queryKey: ['detector', 'status'] })
    },
  })
}

// useAddDefaults merges new built-in rules into the saved set ({ids} adds those, {} all of them)
// or stops offering them ({dismiss}): POST /api/detector/rules/add-defaults.
export function useAddDefaults() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { ids?: string[]; dismiss?: string[] }) => post<RulesView>('/api/detector/rules/add-defaults', body),
    onSuccess: (v) => {
      qc.setQueryData(['detector', 'rules'], v)
      void qc.invalidateQueries({ queryKey: ['detector', 'status'] })
    },
  })
}
