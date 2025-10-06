# Use Ubuntu base image
FROM ubuntu:20.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt update && apt install -y \
    python3 python3-pip curl wget gnupg \
    libnss3 libatk-bridge2.0-0 libdrm2 \
    libxcomposite1 libxdamage1 libxrandr2 \
    libgbm1 libxss1 libasound2 \
    && apt clean

# Install Playwright system dependencies
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
RUN apt install -y nodejs

# Set working directory
WORKDIR /app

# Copy files
COPY . .

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Install Playwright browsers
RUN playwright install-deps
RUN playwright install chromium

# Expose port
EXPOSE 5000

# Start command
CMD ["gunicorn", "app:app"]
