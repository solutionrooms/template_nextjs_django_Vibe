import { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';
import Link from 'next/link';

/**
 * LoginForm component handles user authentication
 * 
 * Provides a form for username/password login and handles:
 * - Form state management
 * - API authentication requests
 * - Error handling and display
 * - Loading state during API requests
 * - Redirection after successful login
 */
const LoginForm = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  /**
   * Handles form submission for user login
   * 
   * @param e - Form submission event
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      // Get API URL from environment or use default
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      
      // Make login request to the backend
      const response = await axios.post(`${apiUrl}/api/users/login/`, {
        username,
        password,
      });
      
      // Store authentication token in localStorage
      localStorage.setItem('accessToken', response.data.token);
      
      // Redirect to dashboard after successful login
      router.push('/dashboard');
    } catch (err) {
      // Display error message for failed login attempts
      setError('Invalid username or password');
      console.error(err);
    } finally {
      // Reset loading state regardless of outcome
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <h1>Login</h1>
      {error && <div className="error-message">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
        
        <div className="register-link">
          Don't have an account?{' '}
          <Link href="/register" className="link">
            Create an account
          </Link>
        </div>
      </form>
      
      <style jsx>{`
        .login-container {
          max-width: 400px;
          margin: 100px auto;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        
        .form-group {
          margin-bottom: 15px;
        }
        
        label {
          display: block;
          margin-bottom: 5px;
        }
        
        input {
          width: 100%;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        
        button {
          width: 100%;
          padding: 10px;
          background-color: #4a90e2;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        
        button:disabled {
          background-color: #cccccc;
        }
        
        .error-message {
          color: red;
          margin-bottom: 15px;
        }
        
        .register-link {
          margin-top: 20px;
          text-align: center;
        }
        
        .register-link .link {
          color: #4a90e2;
          text-decoration: none;
        }
        
        .register-link .link:hover {
          text-decoration: underline;
        }
      `}</style>
    </div>
  );
};

export default LoginForm; 