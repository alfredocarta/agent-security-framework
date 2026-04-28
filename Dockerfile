FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python train_classifier.py

EXPOSE 8000

CMD ["python", "demo.py"]
