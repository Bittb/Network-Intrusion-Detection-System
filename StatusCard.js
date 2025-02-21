// src/components/StatusCard.js
import React from 'react';

const StatusCard = ({ title, value, icon, color }) => {
  return (
    <div className={`status-card ${color}`}>
      <div className="status-icon">{icon}</div>
      <div className="status-content">
        <h3>{title}</h3>
        <p>{value}</p>
      </div>
    </div>
  );
};

export default StatusCard;
