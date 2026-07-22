FROM python:3.13-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Create an unprivileged account.
RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app app

COPY requirements.txt ./

# Install the required packages
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Copy only the required application files where practical.
COPY --chown=app:app . .

USER app

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["python", "run.py"]
