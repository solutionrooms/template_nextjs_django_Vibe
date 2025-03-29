# Next.js Django Template

A modern full-stack application template with Next.js frontend, Django backend, PostgreSQL database, and Docker deployment.

## 🚀 Overview

This template provides a solid foundation for starting new web applications with:

- **Frontend**: Next.js with TypeScript
- **Backend**: Django REST Framework
- **Database**: PostgreSQL
- **Containerization**: Docker Compose
- **Authentication**: JWT-based authentication system

The template includes a complete authentication system with login/registration flows and a simple dashboard, ready for expansion with your custom features.

## ✨ Features

- **User Authentication**: Registration, login, and JWT authentication
- **Responsive UI**: Mobile-friendly interface
- **API Documentation**: Built-in API documentation
- **Containerized Development**: Consistent development environment
- **Scalable Architecture**: Well-organized code structure

## 🛠️ Getting Started

### Prerequisites

- Docker and Docker Compose installed on your machine

### Installation

1. Clone this repository
   ```bash
   git clone https://github.com/yourusername/your-repo-name.git
   cd your-repo-name
   ```

2. Copy the environment file
   ```bash
   cp .env.sample .env
   ```

3. Build and start the containers
   ```bash
   docker compose up --build
   ```

4. Access the applications:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/api/docs

### Renaming the Project

After cloning the template, you might want to rename it to your own project name:

1. Change the project directory name
   ```bash
   # From the parent directory
   mv template_nextjs_django_Vibe your-project-name
   cd your-project-name
   ```

2. Update project references in files:
   - Update `docker-compose.yml` container names (optional)
   - Update package names in `frontend/package.json`
   - Update project name in Django settings (`backend/config/settings.py`)

3. Remove the existing Git repository and initialize a new one
   ```bash
   # Remove the original Git repository
   rm -rf .git
   
   # Initialize a new Git repository
   git init
   git add .
   git commit -m "Initial commit from template"
   ```

4. Push to your own repository
   ```bash
   # Create a new repository on GitHub/GitLab/etc. first, then:
   git remote add origin https://github.com/yourusername/your-project-name.git
   git branch -M main
   git push -u origin main
   ```

### Creating an Admin User

```bash
docker compose exec backend python manage.py createsuperuser
```

## 📁 Project Structure

```
.
├── backend/                # Django backend application
│   ├── config/             # Project settings
│   ├── api/                # API endpoints
│   ├── users/              # User authentication and management
│   └── ...
├── frontend/               # Next.js frontend application
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── lib/            # Utility functions
│   │   ├── pages/          # Application routes
│   │   └── styles/         # Global styles
│   └── ...
├── docker-compose.yml      # Docker configuration
├── prd.md                  # Product requirements document
└── CLAUDE.md               # Development guidelines
```

## 🧰 Development

### Common Commands

#### Container Management
```bash
# Start all containers
docker compose up -d

# Stop all containers
docker compose down
```

#### Frontend Commands
```bash
# Run Next.js in development mode
docker compose exec frontend npm run dev

# Install a new npm package
docker compose exec frontend npm install package-name

# Run linting
docker compose exec frontend npm run lint

# Build for production
docker compose exec frontend npm run build
```

#### Backend Commands
```bash
# Apply migrations
docker compose exec backend python manage.py migrate

# Create migrations
docker compose exec backend python manage.py makemigrations

# Run tests
docker compose exec backend python manage.py test

# Run specific test class
docker compose exec backend python manage.py test users.tests.TestUserAuth
```

## 📝 Code Guidelines

### Frontend (TypeScript/Next.js)
- Use functional components and hooks
- Use descriptive variable names
- Handle errors at the beginning of functions
- Use named exports for components

### Backend (Python/Django)
- Follow PEP 8 style guide
- Include docstrings for all functions
- Use Django's ORM for database operations
- Implement proper validation for all API endpoints

## 🚢 Deployment

This template is designed to be deployable to any environment that supports Docker:

1. Set up your target environment (cloud provider, VPS, etc.)
2. Clone the repository on your server
3. Configure the `.env` file with production settings
4. Build and start the containers:
   ```bash
   docker compose up -d --build
   ```
5. Set up a reverse proxy (Nginx, Traefik, etc.) for production use

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- This template is designed to help you start your next web application quickly
- Customize it to fit your specific project requirements