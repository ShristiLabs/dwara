FROM python:3.12-alpine

# The mock IdP signs RS256 JWTs by shelling out to the openssl CLI
# (python's stdlib has no RSA). The alpine python image ships libcrypto
# but not the CLI, so install it explicitly.
RUN apk add --no-cache openssl

COPY server.py /server.py

ENV PORT=8080
EXPOSE 8080

CMD ["python3", "/server.py"]
