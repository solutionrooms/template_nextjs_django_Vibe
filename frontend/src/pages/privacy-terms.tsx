import React from 'react';
import Link from 'next/link';

export default function PrivacyTerms() {
  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-2xl font-bold mb-4">Privacy Statement</h1>
      <p className="mb-4">Privacy Statement to be included here.</p>
      <Link href="/" className="text-blue-500 hover:underline">
        Return to Home
      </Link>
    </div>
  );
}