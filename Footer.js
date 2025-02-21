import React from "react";
import "../styles/Footer.css";

function Footer() {
  return (
    <footer className="footer">
      <p>
        NIDS Project &copy; 2024 •{" "}
        <a href="https://github.com/your-repo" target="_blank" rel="noopener noreferrer">
          GitHub
        </a>{" "}
        • <a href="/docs">Docs</a>
      </p>
    </footer>
  );
}

export default Footer;

