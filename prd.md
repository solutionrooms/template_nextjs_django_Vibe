#  Project Requirements Document

## 1. Authentication

### Login
**Overview:**
User authentication system that allows users to log in to the application with their credentials.

**Frontend Route:** `/login`

**Features:**
- User login with username and password
- Token-based authentication
- Error handling for invalid credentials

**Access Requirements:**
- Login page: All users

**Underlying API Calls:**
- `POST /api/users/login/`
  - Request: `{ username, password }`
  - Response: User details and authentication token

### Registration
**Overview:**
System to allow new users to create an account on the platform.

**Frontend Route:** `/register`

**Features:**
- User registration with username, email, password
- Optional fields for first name, last name, and postcode
- Password validation
- Error handling for registration issues

**Access Requirements:**
- Registration page: All users

**Underlying API Calls:**
- `POST /api/users/register/`
  - Request: `{ username, password, email, first_name, last_name, postcode }`
  - Response: Confirmation of successful registration with authentication token

## 2. Dashboard

**Overview:**
Protected page that displays the user's profile information after successful authentication.

**Frontend Route:** `/dashboard`

**Features:**
- Displays user information
- Authentication check and redirect for unauthorized users
- Logout functionality

**Access Requirements:**
- Dashboard page: Authenticated users only

**Underlying API Calls:**
- `GET /api/users/me/`
  - Request: Requires authentication token in header
  - Response: Current user details