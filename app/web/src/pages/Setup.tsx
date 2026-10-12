import { useSetupState } from '../api/queries'
import { useT } from '../i18n'
import { Banner, Button } from '../ui/ui'
import SetupWizard from './setup/SetupWizard'

export default function SetupPage() {
  const t = useT()
  const q = useSetupState()
  if (q.isPending) return <div className="center-page boot">{t('loading')}</div>
  if (q.error || !q.data)
    return (
      <div className="center-page">
        <Banner kind="error" title={t('err.network')} />
        <Button onClick={() => void q.refetch()}>{t('retry')}</Button>
      </div>
    )
  return <SetupWizard defaults={q.data.defaults ?? {}} />
}
