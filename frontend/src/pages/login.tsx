import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import LoginForm from '../components/LoginForm';
import axios from 'axios';

export default function Login() {
  const router = useRouter();
  const [debugInfo, setDebugInfo] = useState('');
  
  useEffect(() => {
    // Check if user is already logged in
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('accessToken');
      if (token) {
        router.push('/dashboard');
      }
    }
  }, [router]);

  // Debug function to test auth system
  const runDebugLogin = async () => {
    try {
      setDebugInfo('Attempting debug login...');
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      
      // Try to log in with admin/pass (development credentials)
      const loginResponse = await axios.post(`${apiUrl}/api/users/login/`, {
        username: 'admin',
        password: 'pass',
      });
      
      const token = loginResponse.data.token;
      setDebugInfo(prevInfo => prevInfo + `\nLogin successful, token: ${token.substring(0, 10)}...`);
      
      // Store token
      localStorage.setItem('accessToken', token);
      
      // Try to get user data
      try {
        const userResponse = await axios.get(`${apiUrl}/api/users/me/`, {
          headers: {
            'Authorization': `Token ${token}`
          }
        });
        
        setDebugInfo(prevInfo => prevInfo + `\nUser fetch successful: ${JSON.stringify(userResponse.data)}`);
        
        // Redirect to dashboard after 3 seconds
        setTimeout(() => {
          router.push('/dashboard');
        }, 3000);
      } catch (userError) {
        setDebugInfo(prevInfo => prevInfo + `\nUser fetch failed: ${userError.message}`);
        if (userError.response) {
          setDebugInfo(prevInfo => prevInfo + `\nStatus: ${userError.response.status}, Data: ${JSON.stringify(userError.response.data)}`);
        }
      }
    } catch (error) {
      setDebugInfo(prevInfo => prevInfo + `\nLogin failed: ${error.message}`);
      if (error.response) {
        setDebugInfo(prevInfo => prevInfo + `\nStatus: ${error.response.status}, Data: ${JSON.stringify(error.response.data)}`);
      }
    }
  };

  return (
    <div>
      <LoginForm />
      
      {/* Debug section */}
      <div style={{ marginTop: '50px', padding: '20px', border: '1px solid #ccc', maxWidth: '600px', margin: '0 auto' }}>
        <h3>Debug Tools</h3>
        <button 
          onClick={runDebugLogin}
          style={{ 
            padding: '10px 15px', 
            backgroundColor: '#4CAF50', 
            color: 'white', 
            border: 'none', 
            borderRadius: '4px',
            cursor: 'pointer',
            marginBottom: '10px'
          }}
        >
          Run Debug Login
        </button>
        
        {debugInfo && (
          <pre style={{ 
            backgroundColor: '#f5f5f5', 
            padding: '10px', 
            borderRadius: '4px', 
            overflowX: 'auto',
            whiteSpace: 'pre-wrap'
          }}>
            {debugInfo}
          </pre>
        )}
      </div>
    </div>
  );
}