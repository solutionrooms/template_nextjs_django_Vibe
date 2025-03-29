import { useEffect } from 'react';
import { useRouter } from 'next/router';
import RegisterForm from '../components/RegisterForm';

export default function Register() {
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
      <RegisterForm />
    </div>
  );
} 