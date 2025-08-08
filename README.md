# Cloud Security Scanner v0.2

This version evolves the Cloud Security Scanner from a simple command-line script into a web-based API using the Flask framework. The core scanning logic is now exposed via an HTTP endpoint, allowing it to be integrated with other tools or a future web interface.

## Features

- **Web API:** The S3 scanner can be triggered by sending a GET request to an API endpoint.
- **JSON Output:** Scan results are returned in a structured JSON format, making them easy to parse and use in other applications.
- **Modular Code:** The scanning logic (`s3_scanner.py`) is now a module that is imported and used by the web server (`app.py`).

## How to Use

### Prerequisites

- Python 3
- An AWS account with credentials configured on your machine.

### Setup

1. Clone the repository or download the files.
2. Install the required libraries:
   
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application

1. Start the Flask web server from your terminal:
   
   ```bash
   python app.py
   ```

2. The server will start running on `http://127.0.0.1:5000`.

3. To trigger a scan, open your web browser or use a tool like Postman to access the following URL:
   
   ```
   [http://127.0.0.1:5000/api/v1/scan](http://127.0.0.1:5000/api/v1/scan)
   ```
   
   The scan results will be displayed in your browser as a JSON object.
