# Redirection Containers:

<p align="center">
  <img src="https://github.com/RoseSecurity-Research/Red-Teaming-TTPs/assets/72598486/d302012e-a4f4-4859-b51f-c0a8df7c4203" alt="docker" width="70%"/>
</p>

## Background:

This repository contains a Python script and Docker file designed to serve as a versatile redirection tool for Red Team operations. The tool enables Red Team operators to dynamically control and manipulate network traffic, providing adaptability, scalability, and evasion capabilities.


## Redirector.py:

This script creates a basic Flask web application that serves a fake HTML page at the root route `/`. It has additional routes for `/healthz` and `/callback`. The `/healthz` route returns a simple "Healthy" response for healthchecks. The main logic is in the `/callback` route. It checks the request User-Agent header and if it exactly matches a specific Chrome browser string, it redirects the request to http://10.0.0.2. For any other user agents, it just returns the root page. The script is configured to run on port 443 instead of the default Flask port 5000. It also has a Dockerfile to containerize it, exposing port 443 and adding a healthcheck using the `/healthz` endpoint.

```python
from flask import Flask, request, redirect
app = Flask(__name__)


@app.route('/')
def index():
    return '''
    <html>
      <head>
        <title>Redirection Website</title>
      </head>
      <body>
        <h1>Welcome to my redirector website!</h1>
      </body>
    </html>
    '''


@app.route('/healthz')
def healthcheck():
    return "Healthy"


@app.route('/callback')
def callback():
    user_agent = request.headers.get('User-Agent')
    if user_agent == 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36':
        return redirect('http://10.0.0.2')


if __name__ == '__main__':
    app.run(port=443)
```

## Dockerfile:

```dockerfile
FROM python:3.12-slim

WORKDIR /redirector_app

# Copy the current directory contents
ADD . /redirector_app

# Install flask
RUN pip install flask

# Make TCP 443 available
EXPOSE 443

# Ensure container is healthy
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost/healthz || exit 1

# Run when the container launches
CMD ["python3", "redirector.py"]
```
