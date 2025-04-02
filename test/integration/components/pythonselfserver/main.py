from flask import Flask, request, jsonify, Response
import requests
import ssl
from threading import Thread

# Create four Flask applications for different ports
app1 = Flask(__name__)
app2 = Flask(__name__)
app3 = Flask(__name__)
app4 = Flask(__name__)

# Disable SSL warnings for internal HTTPS calls (optional, for development only)
requests.packages.urllib3.disable_warnings()

# API for the first application (Port 8081)
@app1.route('/api1', methods=['GET'])
def api1():
    try:
        # Forward all incoming headers to the internal HTTPS call
        headers = dict(request.headers)

        # Internal HTTPS call to the second API
        response = requests.get('https://localhost:8082/api2', headers=headers, verify=False)
        return jsonify({
            "message": "Internal call to API2 succeeded",
            "api2_response": response.json()
        }), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

# API for the first application (Port 8082)
@app2.route('/api2', methods=['GET'])
def api2():
    try:
        # Forward all incoming headers to the internal HTTPS call
        headers = dict(request.headers)

        # Internal HTTP call to the third API
        response = requests.get('http://localhost:8083/api3', headers=headers, verify=False)
        return jsonify({
            "message": "Internal call to API3 succeeded",
            "api3_response": response.json()
        }), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app3.route("/smoke")
def smoke():
    return Response(status=200)

# API for the first application (Port 8083)
@app3.route('/api3', methods=['GET'])
def api3():
    try:
        # Forward all incoming headers to the internal HTTPS call
        headers = dict(request.headers)

        # Internal HTTPS call to the third API
        response = requests.get('https://localhost:8084/api4', headers=headers, verify=False)
        return jsonify({
            "message": "Internal call to API4 succeeded",
            "api4_response": response.json()
        }), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

# API for the second application (Port 8084)
@app4.route('/api4', methods=['GET'])
def api2():
    return jsonify({"message": "Hello from API4!"}), 200

# Function to run Flask app with HTTP
def run_app(app, port):
    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=False)

# Function to run Flask app with HTTPS
def run_app_ssl(app, port):
    # Generate self-signed certificates for HTTPS (for development only)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    # Run the Flask app
    app.run(host='0.0.0.0', port=port, ssl_context=context, debug=False)

if __name__ == '__main__':
    # Run both Flask apps on different ports in separate threads
    Thread(target=run_app_ssl, args=(app1, 8081)).start()
    Thread(target=run_app_ssl, args=(app2, 8082)).start()
    Thread(target=run_app,     args=(app3, 8083)).start()
    Thread(target=run_app_ssl, args=(app4, 8084)).start()