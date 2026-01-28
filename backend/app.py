# codes by vision
import os
import sys
import re
import joblib
import numpy as np
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils.qr_scanner import decode_qr_code

app = Flask(__name__)
CORS(app)

email_model = None
email_vectorizer = None
url_model = None
url_scaler = None

def load_models():
    global email_model, email_vectorizer, url_model, url_scaler
    model_dir = os.path.join(os.path.dirname(__file__), 'models')
    try:
        email_model = joblib.load(os.path.join(model_dir, 'email_model.pkl'))
        email_vectorizer = joblib.load(os.path.join(model_dir, 'email_vectorizer.pkl'))
        print("✓ Email model loaded successfully")
    except Exception as e:
        print(f"⚠ Warning: Could not load email model: {e}")
    try:
        url_model = joblib.load(os.path.join(model_dir, 'url_model.pkl'))
        url_scaler = joblib.load(os.path.join(model_dir, 'url_scaler.pkl'))
        print("✓ URL model loaded successfully")
    except Exception as e:
        print(f"⚠ Warning: Could not load URL model: {e}")

def extract_url_features(url):
    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('_'))
    features.append(url.count('/'))
    features.append(url.count('?'))
    features.append(url.count('='))
    features.append(url.count('@'))
    features.append(url.count('&'))
    features.append(1 if url.startswith('https://') else 0)
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else 0)
    suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'banking', 
                          'confirm', 'suspend', 'click', 'urgent', 'password', 'paypal']
    features.append(sum(1 for keyword in suspicious_keywords if keyword in url.lower()))
    domain_part = url.split('/')[2] if len(url.split('/')) > 2 else url
    features.append(len(domain_part))
    features.append(url.count('//') - 1)
    features.append(1 if url.count('-') > 3 else 0)
    return features

@app.route('/')
def index():
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')
    return send_from_directory(frontend_dir, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')
    return send_from_directory(frontend_dir, path)

@app.route('/detect/email', methods=['POST'])
def detect_email():
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'No email text provided'}), 400
        email_text = data['text'].strip()
        if not email_text:
            return jsonify({'error': 'Email text is empty'}), 400
        if email_model is None or email_vectorizer is None:
            return jsonify({'error': 'Email model not loaded. Please train the model first.'}), 500
        email_vectorized = email_vectorizer.transform([email_text])
        prediction = email_model.predict(email_vectorized)[0]
        probability = email_model.predict_proba(email_vectorized)[0]
        confidence = max(probability) * 100
        result = "Phishing" if prediction == 1 else "Legitimate"
        return jsonify({
            'result': result,
            'confidence': f"{confidence:.1f}%",
            'raw_confidence': float(confidence)
        })
    except Exception as e:
        return jsonify({'error': f'Error processing email: {str(e)}'}), 500

@app.route('/detect/url', methods=['POST'])
def detect_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL is empty'}), 400
        if url_model is None or url_scaler is None:
            return jsonify({'error': 'URL model not loaded. Please train the model first.'}), 500
        features = extract_url_features(url)
        features_array = np.array([features])
        features_scaled = url_scaler.transform(features_array)
        prediction = url_model.predict(features_scaled)[0]
        probability = url_model.predict_proba(features_scaled)[0]
        confidence = max(probability) * 100
        result = "Phishing" if prediction == 1 else "Legitimate"
        return jsonify({
            'result': result,
            'confidence': f"{confidence:.1f}%",
            'raw_confidence': float(confidence)
        })
    except Exception as e:
        return jsonify({'error': f'Error processing URL: {str(e)}'}), 500

@app.route('/detect/qr', methods=['POST'])
def detect_qr():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        image_file = request.files['image']
        if image_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        image_data = image_file.read()
        decoded_url, error = decode_qr_code(image_data)
        if error and not decoded_url:
            return jsonify({'error': error}), 400
        if url_model is None or url_scaler is None:
            return jsonify({
                'decoded_url': decoded_url,
                'result': 'Unknown',
                'confidence': 'N/A',
                'error': 'URL model not loaded'
            })
        features = extract_url_features(decoded_url)
        features_array = np.array([features])
        features_scaled = url_scaler.transform(features_array)
        prediction = url_model.predict(features_scaled)[0]
        probability = url_model.predict_proba(features_scaled)[0]
        confidence = max(probability) * 100
        result = "Phishing" if prediction == 1 else "Legitimate"
        response = {
            'decoded_url': decoded_url,
            'result': result,
            'confidence': f"{confidence:.1f}%",
            'raw_confidence': float(confidence)
        }
        if error:
            response['warning'] = error
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': f'Error processing QR code: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'email_model_loaded': email_model is not None,
        'url_model_loaded': url_model is not None
    })

if __name__ == '__main__':
    print("=" * 60)
    print("PhishX - Phishing Detection API")
    print("=" * 60)
    print("\nLoading ML models...")
    load_models()
    print("\nStarting Flask server...")
    print("API will be available at: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
