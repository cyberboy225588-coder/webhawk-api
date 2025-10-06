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

# Install Playwright deps
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
RUN apt install
