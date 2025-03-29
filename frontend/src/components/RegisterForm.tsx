import { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';
import Link from 'next/link';

const RegisterForm = () => {
  const router = useRouter();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    first_name: '',
    last_name: '',
    postcode: '',
    password: '',
    acceptedTerms: false
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value
    });
    
    // Clear error when field is edited
    if (errors[name]) {
      setErrors({
        ...errors,
        [name]: ''
      });
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email is invalid';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters long';
    }

    if (!formData.acceptedTerms) {
      newErrors.acceptedTerms = 'You must accept the terms';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await axios.post(`${apiUrl}/api/users/register/`, {
        username: formData.username,
        email: formData.email,
        first_name: formData.first_name,
        last_name: formData.last_name,
        postcode: formData.postcode,
        password: formData.password
      });
      
      // Store tokens
      localStorage.setItem('accessToken', response.data.token);
      
      // Redirect to dashboard
      router.push('/dashboard');
    } catch (err: any) {
      if (axios.isAxiosError(err) && err.response?.data?.error) {
        // Handle specific API errors
        const errorMsg = err.response.data.error;
        
        if (errorMsg.includes('Username already exists')) {
          setErrors({ ...errors, username: 'Username already exists' });
        } else if (errorMsg.includes('Email already exists')) {
          setErrors({ ...errors, email: 'Email already exists' });
        } else if (errorMsg.includes('Password')) {
          setErrors({ ...errors, password: errorMsg });
        } else {
          setErrors({ ...errors, general: errorMsg });
        }
      } else {
        // Generic error handling
        setErrors({ ...errors, general: 'Registration failed. Please try again.' });
      }
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  return (
    <div className="register-container">
      <h1>Create an Account</h1>
      
      {errors.general && <div className="error-message">{errors.general}</div>}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <div className="input-wrapper">
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              className={errors.username ? 'error' : ''}
            />
            {errors.username && <div className="error-icon">⚠️</div>}
          </div>
          {errors.username && <div className="error-text">{errors.username}</div>}
        </div>
        
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            className={errors.email ? 'error' : ''}
          />
          {errors.email && <div className="error-text">{errors.email}</div>}
        </div>
        
        <div className="form-group">
          <label htmlFor="first_name">First Name</label>
          <input
            type="text"
            id="first_name"
            name="first_name"
            value={formData.first_name}
            onChange={handleChange}
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="last_name">Last Name</label>
          <input
            type="text"
            id="last_name"
            name="last_name"
            value={formData.last_name}
            onChange={handleChange}
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="postcode">Postcode</label>
          <input
            type="text"
            id="postcode"
            name="postcode"
            value={formData.postcode}
            onChange={handleChange}
          />
        </div>
        
        <div className="form-group terms-group">
          <input
            type="checkbox"
            id="acceptedTerms"
            name="acceptedTerms"
            checked={formData.acceptedTerms}
            onChange={handleChange}
            className={errors.acceptedTerms ? 'error' : ''}
          />
          <label htmlFor="acceptedTerms">
            I confirm that I have read and agree with the{' '}
            <Link href="/privacy-terms" className="link">
              privacy terms
            </Link>
          </label>
          {errors.acceptedTerms && <div className="error-text">{errors.acceptedTerms}</div>}
        </div>
        
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <div className="password-input-wrapper">
            <input
              type={showPassword ? 'text' : 'password'}
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              className={errors.password ? 'error' : ''}
            />
            <button 
              type="button" 
              className="password-toggle" 
              onClick={togglePasswordVisibility}
            >
              {showPassword ? '👁️' : '👁️'}
            </button>
          </div>
          {errors.password && <div className="error-text">{errors.password}</div>}
          <div className="password-requirements">
            Password must be at least 8 characters long and contain at least 2 of the following: uppercase letters, lowercase letters, numbers, special characters
          </div>
        </div>
        
        <button type="submit" disabled={loading} className="submit-button">
          {loading ? 'Creating account...' : 'Create Account'}
        </button>
        
        <div className="login-link">
          Already have an account?{' '}
          <Link href="/login" className="link">
            Log in
          </Link>
        </div>
      </form>
      
      <style jsx>{`
        .register-container {
          max-width: 500px;
          margin: 40px auto;
          padding: 20px;
        }
        
        h1 {
          font-size: 28px;
          text-align: center;
          margin-bottom: 30px;
        }
        
        .form-group {
          margin-bottom: 20px;
        }
        
        label {
          display: block;
          margin-bottom: 8px;
          font-weight: 500;
        }
        
        input {
          width: 100%;
          padding: 12px;
          border: 1px solid #ccc;
          border-radius: 4px;
          font-size: 16px;
        }
        
        input.error {
          border-color: #e53e3e;
        }
        
        .error-text {
          color: #e53e3e;
          margin-top: 5px;
          font-size: 14px;
        }
        
        .error-message {
          background-color: #fed7d7;
          color: #e53e3e;
          padding: 10px;
          border-radius: 4px;
          margin-bottom: 20px;
        }
        
        .input-wrapper {
          position: relative;
        }
        
        .error-icon {
          position: absolute;
          right: 10px;
          top: 50%;
          transform: translateY(-50%);
          color: #e53e3e;
        }
        
        .password-input-wrapper {
          position: relative;
        }
        
        .password-toggle {
          position: absolute;
          right: 10px;
          top: 50%;
          transform: translateY(-50%);
          background: none;
          border: none;
          cursor: pointer;
          padding: 0;
          font-size: 16px;
        }
        
        .password-requirements {
          margin-top: 8px;
          font-size: 12px;
          color: #666;
        }
        
        .terms-group {
          display: flex;
          align-items: flex-start;
        }
        
        .terms-group input {
          width: auto;
          margin-right: 10px;
          margin-top: 3px;
        }
        
        .terms-group label {
          margin-bottom: 0;
          line-height: 1.4;
        }
        
        .link {
          color: #3182ce;
          text-decoration: none;
        }
        
        .link:hover {
          text-decoration: underline;
        }
        
        .submit-button {
          width: 100%;
          padding: 12px;
          background-color: #3182ce;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          font-weight: 500;
          cursor: pointer;
          margin-top: 10px;
        }
        
        .submit-button:hover {
          background-color: #2c5282;
        }
        
        .submit-button:disabled {
          background-color: #a0aec0;
          cursor: not-allowed;
        }
        
        .login-link {
          text-align: center;
          margin-top: 20px;
        }
      `}</style>
    </div>
  );
};

export default RegisterForm; 