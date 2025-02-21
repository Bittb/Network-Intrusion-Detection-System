import React, { useState } from "react";
import API from "../services/api";

function ConfigurationForm() {
  const [email, setEmail] = useState("");
  const [threshold, setThreshold] = useState(1500);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const payload = {
      email_alert_enabled: true,
      alert_email: email,
      packet_size_threshold: threshold,
    };
    try {
      await API.post("/update-config", payload);
      alert("Settings updated successfully!");
    } catch (error) {
      console.error("Error updating configuration:", error);
    }
  };

  return (
    <form className="config-form" onSubmit={handleSubmit}>
      <h2>System Configuration</h2>
      <label>
        Alert Email:
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </label>
      <label>
        Packet Size Threshold:
        <input
          type="number"
          value={threshold}
          onChange={(e) => setThreshold(e.target.value)}
        />
      </label>
      <button type="submit">Save Settings</button>
    </form>
  );
}

export default ConfigurationForm;

