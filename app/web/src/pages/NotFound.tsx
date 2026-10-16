import { Compass } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useT } from '../i18n'

export function NotFound() {
  const t = useT()
  return (
    <main className="page">
      <div className="card empty-state">
        <Compass size={28} />
        <h2>{t('notfound.title')}</h2>
        <Link to="/">Current</Link>
      </div>
    </main>
  )
}
