FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install -r requirements.txt


# Copy the rest of the application
COPY . .

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"] 