FROM python:3.13-alpine

# Set environment variables to optimize Python performance
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN adduser --disabled-password --gecos "" appuser
RUN chown -R appuser /app
USER appuser


EXPOSE 9099


CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9099"]