# Cloud Security Scanner v0.3

This version introduces a decoupled frontend, transforming the project into a full-stack web application. The backend now serves a dedicated API, and the user interface is a standalone set of HTML, CSS, and JavaScript files that consume this API.

## Features

- **Decoupled Frontend:** A simple, clean user interface built with HTML, CSS, and vanilla JavaScript.
- **Dynamic Results:** The frontend calls the backend API, fetches the scan results, and dynamically displays them on the page without a reload.
- **CORS Enabled Backend:** The Flask server now uses `Flask-Cors` to allow cross-origin requests from the frontend.

# Cloud Security Scanner v0.2

This version evolves the Cloud Security Scanner from a simple command-line script into a web-based API using the Flask framework. The core scanning logic is now exposed via an HTTP endpoint, allowing it to be integrated with other tools or a future web interface.

## Features

- **Web API:** The S3 scanner can be triggered by sending a GET request to an API endpoint.
- **JSON Output:** Scan results are returned in a structured JSON format, making them easy to parse and use in other applications.
- **Modular Code:** The scanning logic (`s3_scanner.py`) is now a module that is imported and used by the web server (`app.py`).

## How to Use

This version requires running two components: the backend server and the frontend page.

### 1. Run the Backend


1. Navigate to the project's root directory.

### Setup

1. Clone the repository or download the files.
2. Install the required libraries:
   
   ```bash
   pip install -r requirements.txt
   ```
3. Start the Flask web server:
   
   ```bash
   python app.py
   ```
4. The API server will be running on `http://127.0.0.1:5000`.

### 2. Run the Frontend

1. Navigate to the `frontend` folder.
2. Open the `index.html` file directly in your web browser (e.g., by double-clicking it).
3. Click the "Run S3 Scan" button to see the results.
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

