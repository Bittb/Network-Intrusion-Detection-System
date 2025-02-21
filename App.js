import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Home from './pages/Home';
import Logs from './pages/Logs';
import Settings from './pages/Settings';
import { AnalyticsProvider } from './context/AnalyticsContext';
import './styles/App.css';

const App = () => {
  return (
    <AnalyticsProvider>
      <Router>
        <div className="app">
          <Navbar />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </Router>
    </AnalyticsProvider>
  );
};

export default App;
