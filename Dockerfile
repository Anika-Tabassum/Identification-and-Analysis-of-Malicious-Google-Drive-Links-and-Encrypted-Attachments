# Use the official Python image from Docker Hub
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the Python script into the container
COPY app.py /app/

# Install any dependencies needed by your script
RUN pip install --no-cache-dir Flask gdown pyzipper requests

# Expose the port for Flask (if it's running a web server)
EXPOSE 5000

# Command to run your script
CMD ["python", "app.py"]
