// components/BrandedLoader.jsx
import React from "react"
import "./BrandedLoader.css"
import MonImage from "../images/LOGO.png"

const BrandedLoader = () => {
  return (
    <div className="branded-loader">
      <div className="branded-loader-content">
        <img 
          src={MonImage} 
          alt="CFAO Mobility Cameroon Logo" 
          className="loader-logo"
        />
        <div className="progress-bar">
          <div className="progress"></div>
        </div>
        <p className="loader-subtitle">Chargement en cours</p>
      </div>
    </div>
  )
}

export default BrandedLoader