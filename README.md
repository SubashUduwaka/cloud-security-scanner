# Cloud Security Scanner v0.3

This version introduces a decoupled frontend, transforming the project into a full-stack web application. The backend now serves a dedicated API, and the user interface is a standalone set of HTML, CSS, and JavaScript files that consume this API.

## Features

- **Decoupled Frontend:** A simple, clean user interface built with HTML, CSS, and vanilla JavaScript.
- **Dynamic Results:** The frontend calls the backend API, fetches the scan results, and dynamically displays them on the page without a reload.
- **CORS Enabled Backend:** The Flask server now uses `Flask-Cors` to allow cross-origin requests from the frontend.

## How to Use

This version requires running two components: the backend server and the frontend page.

### 1. Run the Backend

1. Navigate to the project's root directory.
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
