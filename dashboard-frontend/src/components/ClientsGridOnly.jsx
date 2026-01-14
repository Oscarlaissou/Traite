import React from 'react';
import { useState } from 'react';
import Header from './Header';
import Sidebar from './Sidebar';
import ClientsGrid from './ClientsGrid';

const ClientsGridOnly = () => {
  const [activeMenuItem, setActiveMenuItem] = useState('Credit compte');
  const [activeSubItem, setActiveSubItem] = useState('Gestion des comptes clients');

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
            <ClientsGrid />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ClientsGridOnly;