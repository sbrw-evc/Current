import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { installScrollbars } from './lib/scrollbars'
import './styles/styles.css'
import './styles/controls.css'
import './styles/app.css'

async function boot() {
  // The mock API is bundled only into a VITE_MOCK=1 build or dev server.
  if (import.meta.env.VITE_MOCK === '1') {
    const { installMock } = await import('./mock')
    installMock()
  }
  installScrollbars()
  const { App } = await import('./App')
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}

void boot()
