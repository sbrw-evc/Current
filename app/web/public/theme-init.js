// Apply the saved (or system) theme before the first paint, so there is no flash. Loaded as a file
// from index.html: the Content-Security-Policy (default-src 'self') forbids inline scripts.
;(function () {
  var t = null
  try {
    t = localStorage.getItem('flow.theme')
  } catch (e) {}
  if (t !== 'light' && t !== 'dark') t = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  document.documentElement.dataset.theme = t
  document.documentElement.style.colorScheme = t
})()
