# Cloud Security Scanner v0.5-alpha

This version expands the scanner's capabilities to include IAM checks and introduces a visual dashboard to summarize the security posture.

## Features

- **IAM Access Key Scanner**: A new module that checks for IAM user access keys that have not been rotated in over 90 days.

- **Dashboard Chart**: The frontend now includes a doughnut chart powered by Chart.js to provide a quick visual summary of "OK" vs. "CRITICAL" findings.

- **Decoupled Frontend:** A simple, clean user interface built with HTML, CSS, and vanilla JavaScript.

- **SQLite Database Integration:** The backend uses `Flask-SQLAlchemy` to save every scan result to a persistent `app.db` file.

- **Historical Scans API Endpoint:** A new endpoint, `/api/v1/history`, has been created to serve all past scan results from the database.

## How to Use

This version requires running two components: the backend server and the frontend page.

### 1. Set Up the Backend

1. Navigate to the project's root directory.

2. Install the required libraries:
   
   ```
   pip install -r requirements.txt
   ```

3. Initialize the Database (First-Time Setup Only)
   
   You need to create the database and its tables. These commands use Flask-Migrate to set up your app.db file.
   
   ```
   # Creates the migrations folder (only run this once per project)
   flask db init
   
   # Generates the initial migration script
   flask db migrate -m "Initial migration."
   
   # Applies the migration to create the database tables
   flask db upgrade
   ```

4. Start the Flask web server:
   
   ```
   python app.py
   ```

5. The API server will be running on `http://127.0.0.1:5000`.

### 2. Run the Frontend

1. Navigate to the `frontend` folder.

2. Open the `index.html` file directly in your web browser (e.g., by double-clicking it).

3. Click the "Run Scan" button to see the results.
