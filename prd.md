#  Project Requirements Document

## 1. Authentication

### Login
**Overview:**
User authentication system that allows users to log in to the application with their credentials.

**Frontend Route:** `/`

**Features:**
- User login with username and password
- Remember me functionality
- Error handling for invalid credentials

**Access Requirements:**
- Login page: All users
- Club selection interface: All users (only displayed for users with multiple club memberships)

**Underlying API Calls:**
- `POST /api/users/login/`
  - Request: `{ username, password, club_id (optional) }`
  - Response: User details, authentication token, and club information
- `POST /api/logout/`
  - Request: Authentication token in header
  - Response: Confirmation of logout

### Registration
**Overview:**
System to allow new users to create an account on the platform.

**Frontend Route:** `/` (shared with login)

**Features:**
- User registration with username, email, first name, last name, and postcode
- Password creation with strength validation
- Privacy policy acceptance requirement
- Error handling for registration issues
- Toggle between login and registration screens

**Access Requirements:**
- Registration page: All users

**Underlying API Calls:**
- `POST /api/users/register/`
  - Request: `{ username, password, email, first_name, last_name, postcode }`
  - Response: Confirmation of successful registration

### Reset Password
**Overview:**
System to allow users to reset their password if forgotten.

**Frontend Route:** `/reset-password`

**Features:**
- Request password reset via email
- Secure token-based password reset
- New password confirmation

**Access Requirements:**
- Password reset request page: All users
- Password reset confirmation page: All users (with valid token)

**Underlying API Calls:**
- `POST /api/reset-password-request/`
  - Request: `{ email }`
  - Response: Confirmation of reset email sent
- `GET /api/validate-reset-token/{token}/`
  - Response: Token validity status
- `POST /api/reset-password/`
  - Request: `{ token, new_password }`
  - Response: Password reset confirmation

## 2. Home Page

**Overview:**
The main landing page after login, providing an overview of user activities and important information.

**Frontend Route:** `/dashboard`

**Features:**
- list user details

**Access Requirements:**
- Dashboard page: All authenticated users

**Underlying API Calls:**
- `GET /api/users/{user_id}/`


