# Zero dependencies: the whole app is Python standard library + static files.
FROM python:3.12-slim

WORKDIR /app
COPY server.py ./
COPY static ./static

ENV CLIPBOARD_HOST=0.0.0.0 \
    CLIPBOARD_PORT=8470 \
    CLIPBOARD_DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 8470

# Run as non-root.
RUN useradd -u 10001 -m app && mkdir -p /data && chown app /data
USER app

CMD ["python3", "server.py"]
