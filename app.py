from flask import Flask, jsonify
from s3_scanner import scan_s3_buckets # our scanner script

app = Flask(__name__)

# api endpoint to run the scan
@app.route('/api/v1/scan', methods=['GET'])
def scan():
    print("-> got scan request")
    results = scan_s3_buckets()
    print("-> scan done")
    
    # send back the json
    return jsonify({"results": results})

# root endpoint to check if it's running
@app.route('/', methods=['GET'])
def index():
    return "API is up. Use /api/v1/scan"

# run the server
if __name__ == '__main__':
    app.run(debug=True)