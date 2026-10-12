import { Navigate, useSearchParams } from 'react-router-dom'
import { incidentState } from '../lib/deeplink'
import { visualizeLink } from './visualize/state'

// /go/incident?ci=&ip=&from=&to= — the "Traffic" link of Umbrella incidents.
export function GoIncident() {
  const [params] = useSearchParams()
  return <Navigate to={visualizeLink(incidentState(params))} replace />
}
