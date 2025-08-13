# app.py
from flask import Flask, jsonify
from flask_cors import CORS
from s3_scanner import run_all_scans
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import datetime

# Let's get Flask up and running.
app = Flask(__name__)

# Gotta tell Flask where our little SQLite database lives.
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Fire up the database and the migration tool.
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# CORS is that thing that lets the frontend talk to the backend. Pretty important.
CORS(app)

# This is basically the blueprint for a row in our database. Simple stuff.
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(64), index=True)
    resource = db.Column(db.String(128))
    status = db.Column(db.String(64))
    issue = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f'<ScanResult {self.resource} - {self.status}>'


# The main event. This kicks off the whole scan when the user clicks the button.
@app.route('/api/v1/scan', methods=['GET'])
def scan():
    print("Received a request to run the scan...")
    scan_results = run_all_scans()
    
    # Time to dump these results into the DB so we don't forget.
    for result in scan_results:
        if "error" not in result:
            db_result = ScanResult(
                service=result['service'],
                resource=result['resource'],
                status=result['status'],
                issue=result['issue']
            )
            db.session.add(db_result)
    
    db.session.commit() # Don't forget to save!
    print("Scan complete. Results saved to database.")

    return jsonify({"scan_results": scan_results})

# Let's dig up old dirt. This grabs everything from the database for the history view.
@app.route('/api/v1/history', methods=['GET'])
def history():
    all_results = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    history_list = [
        {
            "id": r.id,
            "service": r.service,
            "resource": r.resource,
            "status": r.status,
            "issue": r.issue,
            "timestamp": r.timestamp.isoformat()
        } for r in all_results
    ]
    return jsonify({"historical_scans": history_list})

# Just a friendly 'hello' to make sure the server is alive.
@app.route('/', methods=['GET'])
def index():
    return "Hello! Your security scanner API is running. Go to /api/v1/scan to trigger a scan."

# The magic line that starts the server when we run `python app.py`.
if __name__ == '__main__':
    app.run(debug=True)