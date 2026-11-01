FROM python:3.15-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
EXPOSE 8787
CMD ["uig-service", "--host", "0.0.0.0", "--port", "8787"]

