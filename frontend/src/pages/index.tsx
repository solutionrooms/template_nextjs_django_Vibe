import { useEffect } from 'react';
import { useRouter } from 'next/router';

export default function Home() {
  const router = useRouter();
  
  useEffect(() => {
    // Default redirect to login page
    router.push('/login');
  }, [router]);

  return null;
} 