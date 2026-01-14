import React from 'react'
import './Pagination.css'

const Pagination = ({ 
  currentPage, 
  totalPages, 
  totalItems, 
  itemsPerPage, 
  onPageChange, 
  onItemsPerPageChange,
  itemsPerPageOptions = [10, 20, 50, 100],
  showItemsPerPage = true,
  showTotal = true,
  className = ''
}) => {
  // Calculer les pages à afficher
  const getVisiblePages = () => {
    const delta = 2 // Nombre de pages à afficher de chaque côté de la page actuelle
    const range = []
    const rangeWithDots = []

    for (let i = Math.max(2, currentPage - delta); i <= Math.min(totalPages - 1, currentPage + delta); i++) {
      range.push(i)
    }

    if (currentPage - delta > 2) {
      rangeWithDots.push(1, '...')
    } else {
      rangeWithDots.push(1)
    }

    rangeWithDots.push(...range)

    if (currentPage + delta < totalPages - 1) {
      rangeWithDots.push('...', totalPages)
    } else if (totalPages > 1) {
      rangeWithDots.push(totalPages)
    }

    return rangeWithDots
  }

  const visiblePages = getVisiblePages()
  const startItem = (currentPage - 1) * itemsPerPage + 1
  const endItem = Math.min(currentPage * itemsPerPage, totalItems)

  return (
    <div className={`pagination-container ${className}`}>
      <div className="pagination-info">
        {showTotal && (
          <div className="pagination-total">
            Affichage de {startItem} à {endItem} sur {totalItems} résultats
          </div>
        )}
        {showItemsPerPage && (
          <div className="pagination-items-per-page">
            <span>Afficher</span>
            <select 
              value={itemsPerPage} 
              onChange={(e) => onItemsPerPageChange(parseInt(e.target.value))}
              className="pagination-select"
            >
              {itemsPerPageOptions.map(option => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
            <span>par page</span>
          </div>
        )}
      </div>

      <div className="pagination-controls">
        {/* Bouton Première page */}
        <button
          className="pagination-btn pagination-btn-nav"
          onClick={() => onPageChange(1)}
          disabled={currentPage === 1}
          title="Première page"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="11,17 6,12 11,7"></polyline>
            <polyline points="18,17 13,12 18,7"></polyline>
          </svg>
        </button>

        {/* Bouton Page précédente */}
        <button
          className="pagination-btn pagination-btn-nav"
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          title="Page précédente"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="15,18 9,12 15,6"></polyline>
          </svg>
        </button>

        {/* Numéros de pages */}
        <div className="pagination-pages">
          {visiblePages.map((page, index) => (
            <React.Fragment key={index}>
              {page === '...' ? (
                <span className="pagination-dots">...</span>
              ) : (
                <button
                  className={`pagination-btn pagination-btn-page ${
                    page === currentPage ? 'pagination-btn-active' : ''
                  }`}
                  onClick={() => onPageChange(page)}
                  title={`Page ${page}`}
                >
                  {page}
                </button>
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Bouton Page suivante */}
        <button
          className="pagination-btn pagination-btn-nav"
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          title="Page suivante"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="9,18 15,12 9,6"></polyline>
          </svg>
        </button>

        {/* Bouton Dernière page */}
        <button
          className="pagination-btn pagination-btn-nav"
          onClick={() => onPageChange(totalPages)}
          disabled={currentPage === totalPages}
          title="Dernière page"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="13,17 18,12 13,7"></polyline>
            <polyline points="6,17 11,12 6,7"></polyline>
          </svg>
        </button>
      </div>

      {/* Indicateur de page actuelle */}
      <div className="pagination-indicator">
        Page {currentPage} sur {totalPages}
      </div>
    </div>
  )
}

export default Pagination
