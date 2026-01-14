export function formatMoney(value) {
  const numericValue = Number(value || 0)
  if (!isFinite(numericValue)) return value ?? ''
  return new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 0 }).format(numericValue)
}


