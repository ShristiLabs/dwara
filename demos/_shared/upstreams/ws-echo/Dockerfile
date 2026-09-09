FROM python:3.12-alpine
RUN pip install --no-cache-dir websockets
COPY server.py /server.py
ENV PORT=8080
EXPOSE 8080
CMD ["python3", "/server.py"]
