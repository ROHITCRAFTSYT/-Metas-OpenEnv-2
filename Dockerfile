FROM python:3.11-slim

WORKDIR /app

# Install uv - the fast Python package installer (replaces pip)
RUN pip install --no-cache-dir uv

# Copy and install dependencies using uv (10-100x faster than pip)
COPY server/requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

# Copy source code
COPY . .

# Expose port
EXPOSE 8000

# Start FastAPI server
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
