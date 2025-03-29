import { useEffect } from 'react';
import type { AppProps } from 'next/app';
import '../styles/globals.css';
import { setupAxiosInterceptors } from '../lib/auth';

export default function App({ Component, pageProps }: AppProps) {
  useEffect(() => {
    // Setup axios interceptors on client-side only
    if (typeof window !== 'undefined') {
      setupAxiosInterceptors();
    }
  }, []);

  return <Component {...pageProps} />;
} 