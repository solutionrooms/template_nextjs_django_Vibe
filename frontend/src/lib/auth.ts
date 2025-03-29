import axios from 'axios';

/**
 * API base URL from environment or default to localhost development server
 */
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/**
 * Sets up axios interceptors for authentication and token refresh
 * 
 * This function does two key things:
 * 1. Adds authentication token to outgoing requests
 * 2. Handles token refresh when receiving 401 Unauthorized responses
 */
export const setupAxiosInterceptors = () => {
  // Request interceptor: Add auth header to all requests
  axios.interceptors.request.use(
    (config) => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        config.headers['Authorization'] = `Token ${token}`;
        // For debugging
        console.log('Setting Authorization header:', `Token ${token}`);
      }
      return config;
    },
    (error) => {
      return Promise.reject(error);
    }
  );

  // Response interceptor: Handle token refresh on 401 errors
  axios.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config;
      
      // If we get a 401 (Unauthorized) and haven't already tried refreshing
      if (error.response?.status === 401 && !originalRequest._retry) {
        originalRequest._retry = true;
        
        try {
          // For now, just log out as token refresh isn't fully implemented
          console.log('Received 401, logging out');
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          window.location.href = '/login';
          return Promise.reject(error);
        } catch (refreshError) {
          // If refresh fails, clear auth state and redirect to login
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      }
      
      // If error isn't a 401 or refresh failed, reject with original error
      return Promise.reject(error);
    }
  );
};