# PhishX - Advanced Phishing Detection Tool

![PhishX Banner](https://img.shields.io/badge/PhishX-Phishing%20Detection-blue?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0.0-black?style=flat-square&logo=flask)
![ML](https://img.shields.io/badge/ML-scikit--learn-orange?style=flat-square)
![License](https://img.shields.io/badge/License-Educational-red?style=flat-square)

A complete, production-ready phishing detection web application that uses Machine Learning to identify email phishing, URL phishing, and QR code phishing attacks. Built for cybersecurity awareness, research, and defense.

---

## 🎯 Features

### Three Detection Modes

1. **📧 Email Phishing Detection**
   - Analyzes email content using NLP and TF-IDF vectorization
   - Detects deceptive language patterns and urgency tactics
   - Returns confidence score with detailed analysis

2. **🔗 URL Phishing Detection**
   - Extracts 15+ URL-based features (length, special characters, HTTPS, IP usage)
   - Identifies suspicious keywords and domain patterns
   - Uses Random Forest classifier for accurate predictions

3. **📱 QR Code Phishing Detection**
   - Decodes QR codes from uploaded images
   - Extracts embedded URLs automatically
   - Analyzes extracted URLs using the URL phishing model

### Additional Features

- **Real-time Analysis**: Instant results with confidence percentages
- **Clean UI**: Professional, minimal design on white background
- **Animated Counters**: Live statistics for scans, users, and organizations
- **Educational Content**: Learn about phishing types and protection methods
- **Ethical Disclaimer**: Clear guidelines for responsible use

---

## 🛠️ Technology Stack

### Backend
- **Python 3.8+**
- **Flask** - Web framework and API
- **scikit-learn** - Machine Learning models
- **OpenCV & pyzbar** - QR code decoding
- **joblib** - Model serialization

### Frontend
- **HTML5** - Structure
- **TailwindCSS** - Styling (via CDN)
- **Vanilla JavaScript** - Interactivity and API calls

### Machine Learning
- **TF-IDF Vectorization** - Email text analysis
- **Logistic Regression** - Email classification
- **Random Forest** - URL classification
- **Feature Engineering** - URL pattern extraction

---

## 📁 Project Structure

```
PhishX/
├── backend/
│   ├── app.py                    # Flask API server
│   ├── train_email_model.py      # Email model training
│   ├── train_url_model.py        # URL model training
│   ├── requirements.txt          # Python dependencies
│   └── models/                   # Trained models (generated)
│       ├── email_model.pkl
│       ├── email_vectorizer.pkl
│       ├── url_model.pkl
│       └── url_scaler.pkl
├── frontend/
│   ├── index.html                # Main web interface
│   ├── style.css                 # Custom styles
│   └── script.js                 # Frontend logic
├── utils/
│   └── qr_scanner.py             # QR code decoder
└── README.md                     # This file
```

---

## 🚀 Installation & Setup

Follow these steps to get PhishX running locally on your machine.

### 1. Prerequisites

- **Python 3.8 or higher**
- **pip** (Python package manager)
- **System dependencies** for QR code scanning (`pyzbar`):

| Operating System | Command / Action |
| :--- | :--- |
| **Linux (Ubuntu/Debian)** | `sudo apt-get update && sudo apt-get install libzbar0` |
| **macOS** | `brew install zbar` |
| **Windows** | Download and install from [ZBar SourceForge](https://sourceforge.net/projects/zbar/files/) |

### 2. Set Up the Project

#### 📂 Navigate to project root
```bash
cd PhishX
```

#### 🛠️ Create Virtual Environment
If you haven't created one yet:
```bash
python -m venv venv
```

#### 🔌 Activate Virtual Environment

*   **Linux / macOS**:
    ```bash
    source venv/bin/activate
    ```
*   **Windows (Command Prompt)**:
    ```cmd
    venv\Scripts\activate
    ```
*   **Windows (PowerShell)**:
    ```powershell
    .\venv\Scripts\Activate.ps1
    ```

#### 📦 Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 3. Train Machine Learning Models

You MUST train the models before starting the application for the first time:

```bash
# Train the email phishing detection model
python backend/train_email_model.py

# Train the URL phishing detection model
python backend/train_url_model.py
```

### 4. Run the Application

Start the Flask backend server:

```bash
python backend/app.py
```

The application will be available at: **[http://localhost:5000](http://localhost:5000)**

### Step 5: Start Scanning

1. Open your browser and go to `http://localhost:5000`.
2. Use the **Email Analysis**, **Link Checker**, or **QR Code Scan** tools.
3. View the real-time detection results and confidence scores.

---

## 📖 Usage Guide

### Email Analysis

1. Click on **"Email Analysis"** card
2. Paste email content (headers + body) into the textarea
3. Click **"Analyze Email"**
4. View results with confidence score and recommendations

**Example Phishing Email:**
```
URGENT: Your account will be suspended. Click here to verify immediately.
```

### URL Checker

1. Click on **"Link Checker"** card
2. Enter a suspicious URL
3. Click **"Check URL"**
4. View analysis results

**Example Phishing URL:**
```
http://paypal-secure-login.com/verify-account
```

### QR Code Scanner

1. Click on **"QR Code Scan"** card
2. Upload a QR code image (PNG, JPG, SVG)
3. Click **"Scan Image"**
4. View decoded URL and phishing analysis

---

## 🔌 API Documentation

### Base URL
```
http://localhost:5000
```

### Endpoints

#### 1. Email Detection
**POST** `/detect/email`

**Request Body:**
```json
{
  "text": "Your email content here..."
}
```

**Response:**
```json
{
  "result": "Phishing",
  "confidence": "92.5%",
  "raw_confidence": 92.5
}
```

#### 2. URL Detection
**POST** `/detect/url`

**Request Body:**
```json
{
  "url": "https://suspicious-site.com/login"
}
```

**Response:**
```json
{
  "result": "Legitimate",
  "confidence": "87.3%",
  "raw_confidence": 87.3
}
```

#### 3. QR Code Detection
**POST** `/detect/qr`

**Request:** Multipart form data with `image` file

**Response:**
```json
{
  "decoded_url": "http://phishing-site.com",
  "result": "Phishing",
  "confidence": "95.2%",
  "raw_confidence": 95.2
}
```

#### 4. Health Check
**GET** `/health`

**Response:**
```json
{
  "status": "healthy",
  "email_model_loaded": true,
  "url_model_loaded": true
}
```

---

## 🧠 Machine Learning Details

### Email Phishing Model

- **Algorithm**: Logistic Regression
- **Vectorization**: TF-IDF (max 5000 features)
- **Training Data**: 80 synthetic samples (40 phishing, 40 legitimate)
- **Features**: Email text patterns, urgency keywords, suspicious phrases
- **Accuracy**: ~95% on test set

### URL Phishing Model

- **Algorithm**: Random Forest (100 estimators)
- **Features Extracted**: 15 URL-based features
  - URL length
  - Special character counts (., -, _, /, ?, =, @, &)
  - HTTPS presence
  - IP address detection
  - Suspicious keyword count
  - Domain length
  - Multiple slashes
  - Excessive dashes
- **Training Data**: 80 synthetic samples (40 phishing, 40 legitimate)
- **Accuracy**: ~95% on test set

### Model Improvements

For production use, consider:
- **Real-world datasets**: PhishTank, OpenPhish, Enron spam corpus
- **Deep learning**: BERT, LSTM for email analysis
- **External APIs**: VirusTotal, Google Safe Browsing
- **Feature expansion**: WHOIS data, SSL certificate validation
- **Continuous learning**: Regular model retraining with new threats

---

---

## 🎓 Educational Content

### What is Phishing?

Phishing is a cybersecurity attack where attackers impersonate legitimate entities to steal sensitive information like passwords, credit card numbers, or personal data.

### Common Phishing Types

1. **Deceptive Phishing**: Mass emails impersonating brands
2. **Spear Phishing**: Targeted attacks on specific individuals
3. **Whaling**: Attacks targeting executives
4. **Quishing**: QR code-based phishing
5. **Smishing**: SMS-based phishing
6. **Vishing**: Voice call phishing

### Protection Tips

- ✅ Always verify sender email addresses
- ✅ Hover over links before clicking
- ✅ Enable multi-factor authentication (MFA)
- ✅ Keep software updated
- ✅ Use password managers
- ✅ Report suspicious emails
- ✅ Educate yourself and others

---

## 🤝 Contributing

This is an educational project. Contributions for:
- Improved ML models
- Better datasets
- UI/UX enhancements
- Documentation improvements
- Bug fixes

are welcome!

---

## 📄 License

This project is for **educational and research purposes only**. 

**MIT License** - See [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author
**Vision KC**
[Github](https://github.com/vision-dev1)
[Website](https://visionkc.com.np)

---

**⚡ Remember: Stay vigilant, stay secure! ⚡**
