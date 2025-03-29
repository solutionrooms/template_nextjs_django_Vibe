import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import axios from 'axios';

/**
 * Dashboard Component
 * 
 * A protected page that displays the user's dashboard after successful authentication.
 * It fetches the user's profile information and displays a welcome message.
 * Implements authentication check and redirect for unauthenticated users.
 */
export default function Dashboard() {
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    /**
     * Verify authentication and fetch user data
     * 
     * This effect runs on component mount to:
     * 1. Check if the user has a valid access token
     * 2. Redirect to login if no token exists
     * 3. Fetch the user's profile data if authenticated
     * 4. Handle authentication errors by clearing token and redirecting
     */
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('accessToken');
      
      // If no token exists, redirect to login
      if (!token) {
        router.push('/login');
        return;
      }

      /**
       * Fetches the authenticated user's profile information from the API
       */
      const fetchUserData = async () => {
        try {
          const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
          const response = await axios.get(`${apiUrl}/api/users/me/`);
          setUser(response.data);
        } catch (error) {
          console.error('Error fetching user data:', error);
          
          // If unauthorized (token expired/invalid), redirect to login
          if (axios.isAxiosError(error) && error.response?.status === 401) {
            // Clear authentication state
            localStorage.removeItem('accessToken');
            localStorage.removeItem('refreshToken');
            router.push('/login');
          }
        } finally {
          // Update loading state regardless of outcome
          setLoading(false);
        }
      };

      fetchUserData();
    }
  }, [router]);

  /**
   * Handles user logout
   * 
   * Clears authentication tokens from localStorage and redirects to login page
   */
  const handleLogout = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    router.push('/login');
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="dashboard">
      <header>
        <h1>Dashboard</h1>
        <button onClick={handleLogout}>Logout</button>
      </header>
      
      <main>
        <h2>Welcome, {user?.username || 'User'}!</h2>
        <p>This is your dashboard.</p>
      </main>
      
      <style jsx>{`
        .dashboard {
          max-width: 1200px;
          margin: 0 auto;
          padding: 20px;
        }
        
        header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 30px;
          padding-bottom: 10px;
          border-bottom: 1px solid #eee;
        }
        
        button {
          padding: 8px 16px;
          background-color: #f44336;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
      `}</style>
    </div>
  );
} 