import React, { useState, useEffect, useCallback } from "react";
import axios from "../services/api";
import { debounce } from "lodash";
import "../styles/Logs.css";

function Logs() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pagination, setPagination] = useState({
    currentPage: 1,
    totalPages: 1,
    itemsPerPage: 15
  });
  const [sortConfig, setSortConfig] = useState({
    key: 'timestamp',
    direction: 'desc'
  });

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true);
      const response = await axios.get("/logs", {
        params: {
          page: pagination.currentPage,
          itemsPerPage: pagination.itemsPerPage,
          filter,
          sortKey: sortConfig.key,
          sortDirection: sortConfig.direction
        }
      });
      setLogs(response.data.logs);
      setPagination(prev => ({
        ...prev,
        totalPages: Math.ceil(response.data.total / prev.itemsPerPage)
      }));
      setError(null);
    } catch (error) {
      setError("Failed to fetch logs. Please try again later.");
      console.error("Error fetching logs:", error);
    } finally {
      setLoading(false);
    }
  }, [pagination.currentPage, pagination.itemsPerPage, filter, sortConfig]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Debounced filter handler
  const debouncedFilter = debounce((value) => {
    setFilter(value);
    setPagination(prev => ({ ...prev, currentPage: 1 }));
  }, 500);

  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const handleExport = async () => {
    try {
      const response = await axios.get("/export-logs", {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `nids_logs_${new Date().toISOString()}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error("Error exporting logs:", error);
      alert("Failed to export logs. Please try again later.");
    }
  };

  return (
    <div className="logs-container">
      <div className="logs-header">
        <h2>System Logs</h2>
        <div className="logs-actions">
          <input
            type="text"
            placeholder="Search logs..."
            onChange={(e) => debouncedFilter(e.target.value)}
            className="search-input"
          />
          <button onClick={handleExport} className="export-button">
            Export Logs
          </button>
        </div>
      </div>

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}

      {loading ? (
        <div className="loading-spinner">Loading logs...</div>
      ) : (
        <>
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th onClick={() => handleSort('timestamp')}>
                    Timestamp
                    {sortConfig.key === 'timestamp' && (
                      <span className="sort-indicator">
                        {sortConfig.direction === 'asc' ? '↑' : '↓'}
                      </span>
                    )}
                  </th>
                  <th onClick={() => handleSort('anomaly_type')}>Anomaly Type</th>
                  <th onClick={() => handleSort('description')}>Description</th>
                  <th onClick={() => handleSort('packet_size')}>Packet Size</th>
                  <th onClick={() => handleSort('source_ip')}>Source IP</th>
                  <th onClick={() => handleSort('destination_ip')}>Destination IP</th>
                  <th onClick={() => handleSort('protocol')}>Protocol</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, index) => (
                  <tr key={index} className={`severity-${log.severity}`}>
                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                    <td>{log.anomaly_type}</td>
                    <td>{log.description}</td>
                    <td>{log.packet_size}</td>
                    <td>{log.source_ip}</td>
                    <td>{log.destination_ip}</td>
                    <td>{log.protocol}</td>
                    <td>
                      <span className={`severity-badge severity-${log.severity}`}>
                        {log.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination-controls">
            <button
              onClick={() => setPagination(prev => ({ ...prev, currentPage: prev.currentPage - 1 }))}
              disabled={pagination.currentPage === 1}
            >
              Previous
            </button>
            <span>
              Page {pagination.currentPage} of {pagination.totalPages}
            </span>
            <button
              onClick={() => setPagination(prev => ({ ...prev, currentPage: prev.currentPage + 1 }))}
              disabled={pagination.currentPage === pagination.totalPages}
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export default Logs;
