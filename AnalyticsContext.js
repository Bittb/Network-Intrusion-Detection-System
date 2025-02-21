import React, { createContext, useState, useContext } from 'react';

const AnalyticsContext = createContext();

export const AnalyticsProvider = ({ children }) => {
  const [analyticsData, setAnalyticsData] = useState({
    alerts: [],
    metrics: {},
    systemStatus: 'active'
  });

  const updateAnalytics = (newData) => {
    setAnalyticsData(prevData => ({
      ...prevData,
      ...newData
    }));
  };

  return (
    <AnalyticsContext.Provider value={{ analyticsData, updateAnalytics }}>
      {children}
    </AnalyticsContext.Provider>
  );
};

export const useAnalytics = () => useContext(AnalyticsContext);

export default AnalyticsContext;

