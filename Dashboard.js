// src/components/EnhancedDashboard.js
import React from 'react';
import { useAnalytics } from '../context/AnalyticsContext';
import "../styles/Dashboard.css";

const Dashboard = () => {
  const { analyticsData } = useAnalytics();

  return (
    <div className="enhanced-dashboard">
      <div className="dashboard-grid">
        {/* Add your dashboard content here */}
        <h2>System Overview</h2>
        <div className="metrics">
          <p>Status: {analyticsData.systemStatus}</p>
          <p>Total Alerts: {analyticsData.alerts.length}</p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
