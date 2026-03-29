FROM python:3.11-slim

WORKDIR /app

# Install dependencies (--prefer-binary avoids Rust/C compilation)
COPY server/requirements.txt .
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

# Copy source code
COPY . .

# HF Spaces requires port 7860
EXPOSE 7860

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
