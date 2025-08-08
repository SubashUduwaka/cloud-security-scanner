from flask import Flask, jsonify
from flask_cors import CORS
from s3_scanner import scan_s3_buckets

app = Flask(__name__)
CORS(app) # enable CORS

# api endpoint for the scanner
@app.route('/api/v1/scan', methods=['GET'])
def scan():
    print("-> scan request received")
    results = scan_s3_buckets()
    print("-> scan done")

    # send back results as json
    return jsonify({"scan_results": results})

# root to check if the server is up
@app.route('/', methods=['GET'])
def index():
    return "API is running. Use /api/v1/scan to run."

# run the server
if __name__ == '__main__':
    app.run(debug=True)