import axios from "axios";

const API = axios.create({
 baseURL: 'http://localhost:5000', // Backend server URL
  timeout: 5000
});

API.interceptors.response.use(
  response => response,
  error => {
    console.error("API error:", error.message);
    alert("An error occurred while communicating with the backend.");
    return Promise.reject(error);
  }
);

export default API;

