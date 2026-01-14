import React, { useEffect } from "react"

const Toast = ({ title, message, type = 'success', onClose, duration = 4000 }) => {
  useEffect(() => {
    const t = setTimeout(() => { onClose && onClose() }, duration)
    return () => clearTimeout(t)
  }, [duration, onClose])

  const bg = type === 'success' ? '#ecfdf5' : type === 'error' ? '#fee2e2' : '#eff6ff'
  const border = type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'
  const color = type === 'success' ? '#065f46' : type === 'error' ? '#7f1d1d' : '#1e3a8a'

  return (
    <div style={{ position: 'fixed', top: 16, right: 16, zIndex: 9999 }}>
      <div role="status" aria-live="polite" aria-atomic="true" style={{
        minWidth: 260,
        maxWidth: 420,
        background: bg,
        border: `1px solid ${border}`,
        color,
        padding: 12,
        borderRadius: 10,
        boxShadow: '0 8px 24px rgba(0,0,0,0.08)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ fontWeight: 700 }}>{title}</div>
          <button onClick={onClose} aria-label="Fermer" style={{ background: 'transparent', border: 'none', color, cursor: 'pointer' }}>×</button>
        </div>
        {message ? (
          <div style={{ marginTop: 4, fontSize: 14 }}>{message}</div>
        ) : null}
      </div>
    </div>
  )
}

export default Toast


