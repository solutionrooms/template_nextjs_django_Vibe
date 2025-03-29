# Next.js Django Project Guidelines

## Project Overview
This is a Template project for stating vibe coding  with next.js, django, postgres, docker.
It includes just user management and logon screens, together with a dashboard.


## Commands
### Container Management
- `docker compose up -d` - Start all containers
- `docker compose down` - Stop all containers
- `docker compose exec frontend npm run dev` - Run Next.js in dev mode
- `docker compose exec frontend npm run lint` - Lint frontend code
- `docker compose exec frontend npm run build` - Build frontend
- `docker compose exec backend python manage.py test` - Run all backend tests
- `docker compose exec backend python manage.py test users.tests.TestUserAuth` - Run specific test class
- `docker compose exec backend python manage.py makemigrations` - Create migrations
- `docker compose exec backend python manage.py migrate` - Apply migrations

## Code Style Guidelines
### Frontend (TypeScript/Next.js)
- Use functional components and hooks; avoid classes
- Descriptive variable names with auxiliary verbs (e.g., `isLoading`, `hasError`)
- Handle errors at the beginning of functions using early returns
- Use named exports for components and functions
- Use lowercase with dashes for directory names

### Backend (Python/Django)
- Follow PEP 8 style guide for Python code
- Docstrings for all functions, classes, and modules
- Use Django's ORM for database operations
- Proper error handling with try/except blocks where appropriate
- All API endpoints must include proper validation and error responses

### General
- Only run Django inside backend container, Node.js inside frontend container
- Ensure code remains portable for deployment to remote servers
- Write tests for all new functionality