# template_nextjs_django_Vibe
A Tempate for starting a Vibe project on a popular stack

Includes:
- cursor rules. (.cursor folder)
- prd.md (product requirement document) initally set up for just a logon system, Keep this updated with your project features to improve Vibe. 
- a logon system and home page

# Next.js + Django + Posgres Stack

A full-stack application with:
- Next.js frontend
- Django backend
- Postgres database
- Docker Compose setup

# Docker operations
- All operations are performed in docker containers
- - docker-compose.yml is used to define the containers
- - .env is used for all parameters that are either secret or change when app is moved

## Setup

1. Install Docker and Docker Compose

2. Consider renaming the folder to your own app name, then you can add that to your own git repo

2. copy .env.sample to .env

3. Build and run the containers:
```bash
docker compose up --build
```

4. Access the applications:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs

## Development

## Project Structure

```python
.
├── .cursor/            # Cursor rules for AI assistance
├── backend/            # Django backend application
│   ├── config/         # Project settings
│   ├── api/            # API endpoints
│   ├── users/          # User authentication and management
│   └── ...
├── frontend/           # Next.js frontend application
│   ├── components/     # Reusable UI components
│   ├── pages/          # Application routes
│   ├── public/         # Static assets
│   └── ...
└── docker-compose.yml  # Docker configuration
```

- Frontend code is in the `frontend/` directory
- Backend code is in the `backend/` directory

## Common Commands

### Backend Commands

```bash
# Create Django migrations
docker compose exec backend python manage.py makemigrations

# Apply migrations
docker compose exec backend python manage.py migrate

# Create a superuser
docker compose exec backend python manage.py createsuperuser

# Run Django shell
docker compose exec backend python manage.py shell
```

### Frontend Commands

```bash
# Install a new npm package
docker compose exec frontend npm install package-name

# Build for production
docker compose exec frontend npm run build

# Run linting
docker compose exec frontend npm run lint
```

## Deployment

This template is designed to be portable and deployable to any environment that supports Docker. Follow these steps for deployment:

1. Clone the repository on your server
2. Create and configure the `.env` file with production settings
3. Build and start the containers:
   ```bash
   docker compose up -d --build
   ```


