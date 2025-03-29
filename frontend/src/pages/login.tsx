import { useEffect } from 'react';
import { useRouter } from 'next/router';
import LoginForm from '../components/LoginForm';

export default function Login() {
  const router = useRouter();
  
  useEffect(() => {
    // Check if user is already logged in
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('accessToken');
      if (token) {
        router.push('/dashboard');
      }
    }
  }, [router]);

  return (
    <div>
      <LoginForm />
    </div>
  );
} 