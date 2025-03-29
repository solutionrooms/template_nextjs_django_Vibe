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
  const [error, setError] = useState('');

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
      
      // Log token for debugging
      console.log('Token in localStorage:', token ? `${token.substring(0, 10)}...` : 'none');
      
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
          const response = await axios.get(`${apiUrl}/api/users/me/`, {
            headers: {
              'Authorization': `Token ${token}`  // Explicitly set header for this request
            }
          });
          console.log('User data response:', response.data);
          setUser(response.data);
          setError('');
        } catch (error) {
          console.error('Error fetching user data:', error);
          setError(`Error: ${error.message}`);
          
          // If unauthorized (token expired/invalid), redirect to login
          if (axios.isAxiosError(error) && error.response?.status === 401) {
            setError('Authentication failed: ' + JSON.stringify(error.response?.data));
            // Clear authentication state
            localStorage.removeItem('accessToken');
            localStorage.removeItem('refreshToken');
            setTimeout(() => {
              router.push('/login');
            }, 3000); // Short delay to show error before redirect
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
        {error ? (
          <div className="error-message">
            <h3>Authentication Error</h3>
            <p>{error}</p>
            <p>Redirecting to login page...</p>
          </div>
        ) : (
          <>
            <h2>Welcome, {user?.username || 'User'}!</h2>
            <p>This is your dashboard.</p>
            <div className="user-info">
              <h3>Your Information</h3>
              <pre>{JSON.stringify(user, null, 2)}</pre>
            </div>
          </>
        )}
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
        
        .error-message {
          background-color: #ffebee;
          border: 1px solid #ffcdd2;
          border-radius: 4px;
          padding: 15px;
          margin-bottom: 20px;
          color: #c62828;
        }
        
        .user-info {
          background-color: #f5f5f5;
          border-radius: 4px;
          padding: 15px;
          margin-top: 20px;
        }
        
        pre {
          white-space: pre-wrap;
          word-wrap: break-word;
          overflow-x: auto;
        }
      `}</style>
    </div>
  );
}