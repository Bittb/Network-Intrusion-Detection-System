import React from "react";
import Dashboard from "../components/Dashboard";
import { useAnalytics } from "../context/AnalyticsContext";
import StatusCard from "../components/StatusCard";
import "../styles/Home.css";

function Home() {
  const { analyticsData } = useAnalytics();
  const { metrics, systemStatus } = analyticsData;

  return (
    <div className="home">
      <header className="header-section">
        <h1>Network Intrusion Detection System</h1>
        <p className="subtitle">Real-time network monitoring and threat detection</p>
      </header>

      <div className="metrics-grid">
        <StatusCard
          title="Active Threats"
          value={metrics.activeThreats}
          type="danger"
        />
        <StatusCard
          title="Packets Analyzed"
          value={metrics.packetsAnalyzed}
          type="info"
        />
        <StatusCard
          title="Anomalies Detected"
          value={metrics.anomaliesDetected}
          type="warning"
        />
      </div>

      <div className="dashboard-container">
        <Dashboard />
      </div>

      <div className="system-status">
        <h2>System Status</h2>
        <div className="status-indicators">
          <div className="status-item">
            <span
              className={`status-dot ${systemStatus === "active" ? "active" : "inactive"}`}
            ></span>
            <span>IDS Engine</span>
          </div>
          <div className="status-item">
            <span
              className={`status-dot ${metrics.databaseStatus ? "active" : "inactive"}`}
            ></span>
            <span>Database Connection</span>
          </div>
          <div className="status-item">
            <span
              className={`status-dot ${metrics.networkStatus ? "active" : "inactive"}`}
            ></span>
            <span>Network Monitoring</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Home;

