FROM debian:jessie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    python3-minimal python3-dnspython python3-requests \
    python3-coverage \
    && apt-get clean
