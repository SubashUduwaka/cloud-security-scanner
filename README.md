

# Cloud Security Scanner v0.4

This version introduces a decoupled frontend and a persistent database, transforming the project into a full-stack web application. The backend now serves a dedicated API that remembers scan history, and the user interface is a standalone set of HTML, CSS, and JavaScript files that consume this API.

## Features

- **Decoupled Frontend:** A simple, clean user interface built with HTML, CSS, and vanilla JavaScript provides a user-friendly way to run scans and view results. 1

- **Dynamic API Calls:** The frontend uses the `fetch` API to communicate with the backend, allowing for a modern, single-page application feel. 2

- **SQLite Database Integration:** The backend now uses `Flask-SQLAlchemy` to save every scan result to a persistent `app.db` file.

- **Historical Scans API Endpoint:** A new endpoint, `/api/v1/history`, has been created to serve all past scan results from the database.

- **Database Migrations:** The project uses `Flask-Migrate` to manage the database schema.
- **Decoupled Frontend:** A simple, clean user interface built with HTML, CSS, and vanilla JavaScript.
- **Dynamic Results:** The frontend calls the backend API, fetches the scan results, and dynamically displays them on the page without a reload.
- **CORS Enabled Backend:** The Flask server now uses `Flask-Cors` to allow cross-origin requests from the frontend.
ec57fe706f6b906f40527be97145e576417adea5

## How to Use

This version requires running two components: the backend server and the frontend page.

### 1. Set Up the Backend

1. Navigate to the project's root directory.


### Setup

2. Install the required libraries:
   
   Bash
   
   ```
   pip install -r requirements.txt
   ```

3. Initialize the Database (First-Time Setup Only)
   
   You need to create the database and its tables. These commands use Flask-Migrate to set up your app.db file.
   
   Bash
   
   ```
   # Creates the migrations folder (only run this once per project)
   flask db init
   
   # Generates the initial migration script
   flask db migrate -m "Initial migration."
   
   # Applies the migration to create the database tables
   flask db upgrade
   ```

4. Start the Flask web server:
   
   Bash
   
   ```
   python app.py
   ```

5. The API server will be running on `http://127.0.0.1:5000`.

### 2. Run the Frontend

1. Navigate to the `frontend` folder.

2. Open the `index.html` file directly in your web browser (e.g., by double-clicking it).

3. Click the "Run Scan" button to see the results.

3. Click the "Run S3 Scan" button to see the results.
