import React, { useState, useEffect } from "react";
import axios from "../utils/api";
import { FaFilter, FaDownload } from "react-icons/fa";
import "../styles/AnomaliesTable.css";

function AnomaliesTable() {
  const [anomalies, setAnomalies] = useState([]);
  const [filter, setFilter] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  const [loading, setLoading] = useState(true);
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  useEffect(() => {
    const fetchAnomalies = async () => {
      try {
        const response = await axios.get("/anomalies");
        setAnomalies(response.data);
      } catch (error) {
        console.error("Error fetching anomalies:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchAnomalies();
    const interval = setInterval(fetchAnomalies, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const handleSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const sortedAnomalies = React.useMemo(() => {
    if (!sortConfig.key) return anomalies;

    return [...anomalies].sort((a, b) => {
      if (a[sortConfig.key] < b[sortConfig.key]) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      if (a[sortConfig.key] > b[sortConfig.key]) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }, [anomalies, sortConfig]);

  const filteredAnomalies = sortedAnomalies.filter((anomaly) =>
    Object.values(anomaly).some(value => 
      value.toString().toLowerCase().includes(filter.toLowerCase())
    )
  );

  const exportToCSV = () => {
    const headers = ["Timestamp", "Anomaly Type", "Description", "Packet Size", "Source IP", "Destination IP", "Protocol"];
    const csvContent = [
      headers.join(","),
      ...filteredAnomalies.map(anomaly => 
        headers.map(header => JSON.stringify(anomaly[header.toLowerCase().replace(" ", "_")])).join(",")
      )
    ].join("\n");

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "anomalies_export.csv";
    link.click();
  };

  return (
    <div className="anomalies">
      <div className="table-header">
        <div className="filter-section">
          <input
            type="text"
            placeholder="Search anomalies..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <FaFilter />
        </div>
        <button className="export-button" onClick={exportToCSV}>
          <FaDownload /> Export to CSV
        </button>
      </div>

      {loading ? (
        <div className="loading">Loading anomalies...</div>
      ) : (
        <>
          <div className="table-container">
            <table className="anomalies-table">
              <thead>
                <tr>
                  {["Timestamp", "Anomaly Type", "Description", "Packet Size", "Source IP", "Destination IP", "Protocol"].map(header => (
                    <th 
                      key={header} 
                      onClick={() => handleSort(header.toLowerCase().replace(" ", "_"))}
                      className={sortConfig.key === header.toLowerCase().replace(" ", "_") ? `sorted-${sortConfig.direction}` : ''}
                    >
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredAnomalies
                  .slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)
                  .map((anomaly, index) => (
                    <tr key={index} className={anomaly.severity >= 4 ? 'high-severity' : ''}>
                      <td>{anomaly.timestamp}</td>
                      <td>{anomaly.anomaly_type}</td>
                      <td>{anomaly.description}</td>
                      <td>{anomaly.packet_size}</td>
                      <td>{anomaly.source_ip}</td>
                      <td>{anomaly.destination_ip}</td>
                      <td>{anomaly.protocol}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            {[...Array(Math.ceil(filteredAnomalies.length / itemsPerPage))].map((_, i) => (
              <button
                key={i}
                onClick={() => setCurrentPage(i + 1)}
                className={currentPage === i + 1 ? "active" : ""}
              >
                {i + 1}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export default AnomaliesTable;
