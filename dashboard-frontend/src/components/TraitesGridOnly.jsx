import React from 'react';
import { useState } from 'react';
import Header from './Header';
import Sidebar from './Sidebar';
import TraitesGrid from './TraitesGrid';

const TraitesGridOnly = () => {
  const [activeMenuItem, setActiveMenuItem] = useState('Gestion Traites');
  const [activeSubItem, setActiveSubItem] = useState('Grille de saisie');

  return (
    <div className="dashboard-container">
      <div className="dashboard-wrapper">
        <Sidebar 
          activeMenuItem={activeMenuItem} 
          activeSubItem={activeSubItem}
          setActiveMenuItem={setActiveMenuItem}
          setActiveSubItem={setActiveSubItem}
        />
        <div className="main-content">
          <Header />
          <div className="content-area">
            {/* Only show the grid without dashboard statistics */}
            <TraitesGrid />
          </div>
        </div>
      </div>
    </div>
  );
};

export default TraitesGridOnly;