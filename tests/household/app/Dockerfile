FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN pip install --no-cache-dir requests==2.34.2 PyJWT==2.15.1 cryptography==50.0.2 PyYAML==6.0.3 ldap3==2.9.1
WORKDIR /app
COPY . .
CMD ["python", "server.py"]
