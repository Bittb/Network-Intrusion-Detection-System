import React from "react";
import { Link } from "react-router-dom";
import { AiFillHome, AiFillSetting } from "react-icons/ai";
import { FaListAlt } from "react-icons/fa";
import "../styles/Navbar.css";

function Navbar() {
  return (
    <nav className="navbar">
      <h1>NIDS Dashboard</h1>
      <ul className="nav-links">
        <li>
          <Link to="/">
            <AiFillHome /> Home
          </Link>
        </li>
        <li>
          <Link to="/logs">
            <FaListAlt /> Logs
          </Link>
        </li>
        <li>
          <Link to="/settings">
            <AiFillSetting /> Settings
          </Link>
        </li>
      </ul>
    </nav>
  );
}

export default Navbar;

