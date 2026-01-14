import React from "react"
import { CheckCircle } from "lucide-react"

const SuccessDialog = ({ isOpen, onClose, title, message, numero, montant }) => {
  if (!isOpen) return null

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999
    }}>
      <div style={{
        backgroundColor: '#ffffff',
        borderRadius: 12,
        padding: 24,
        maxWidth: 400,
        width: '90%',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        textAlign: 'center'
      }}>
        {/* Icône de succès */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          marginBottom: 16
        }}>
          <div style={{
            width: 64,
            height: 64,
            borderRadius: '50%',
            backgroundColor: '#10b981',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <CheckCircle size={32} color="white" />
          </div>
        </div>

        {/* Titre */}
        <h3 style={{
          color: '#065f46',
          fontSize: 20,
          fontWeight: 700,
          margin: '0 0 8px 0'
        }}>
          {title}
        </h3>

        {/* Message */}
        <p style={{
          color: '#374151',
          fontSize: 16,
          margin: '0 0 16px 0',
          lineHeight: 1.5
        }}>
          {message}
        </p>

        {/* Détails de la traite */}
        <div style={{
          backgroundColor: '#f0fdf4',
          border: '1px solid #bbf7d0',
          borderRadius: 8,
          padding: 16,
          marginBottom: 20
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 8
          }}>
            <span style={{ color: '#374151', fontWeight: 600 }}>Numéro:</span>
            <span style={{ color: '#065f46', fontWeight: 700 }}>{numero}</span>
          </div>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span style={{ color: '#374151', fontWeight: 600 }}>Montant:</span>
            <span style={{ color: '#065f46', fontWeight: 700 }}>{montant}</span>
          </div>
        </div>

        {/* Bouton de fermeture */}
        <button
          onClick={onClose}
          style={{
            backgroundColor: '#10b981',
            color: 'white',
            border: 'none',
            borderRadius: 8,
            padding: '12px 24px',
            fontSize: 16,
            fontWeight: 600,
            cursor: 'pointer',
            width: '100%',
            transition: 'background-color 0.2s'
          }}
          onMouseEnter={(e) => e.target.style.backgroundColor = '#059669'}
          onMouseLeave={(e) => e.target.style.backgroundColor = '#10b981'}
        >
          Continuer
        </button>
      </div>
    </div>
  )
}

export default SuccessDialog
