FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system deps
RUN apt update && apt install -y \
    python3 python3-pip curl wget gnupg \
    libnss3 libatk-bridge2.0-0 libdrm2 \
    libxcomposite1 libxdamage1 libxrandr2 \
    libgbm1 libxss1 libasound2 \
    nmap \
    && apt clean

# Install Node.js for Playwright
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
RUN apt install -y nodejs

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Install Playwright browsers
RUN npx playwright install-deps
RUN npx playwright install chromium

# Copy app
COPY . .

# Expose port
EXPOSE 5000

# Run app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
