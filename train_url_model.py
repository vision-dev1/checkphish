# codes by vision
import os
import re
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report

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

def create_training_data():
    phishing_urls = [
        "http://paypal-secure-login.com/verify-account",
        "https://192.168.1.1/banking/login.php",
        "http://www.amazon-security-update.net/confirm",
        "https://accounts-google.com/signin/verify",
        "http://secure-banking-login.xyz/update",
        "https://microsoft-account-verify.com/urgent",
        "http://apple-id-locked.net/unlock-account",
        "https://facebook-security-check.com/verify",
        "http://netflix-payment-update.org/billing",
        "https://paypal.com-secure.verification.net/login",
        "http://chase-bank-alert.com/confirm-identity",
        "https://amazon.com-order-12345.net/cancel",
        "http://irs-tax-refund.gov.claim.net/process",
        "https://wellsfargo-online-banking.net/signin",
        "http://usps-package-delivery.com/reschedule",
        "https://instagram-verify-account.net/confirm",
        "http://linkedin-security-alert.com/verify",
        "http://dropbox-storage-full.net/upgrade",
        "https://twitter-account-suspended.com/appeal",
        "http://ebay-seller-verification.net/confirm",
        "https://steam-account-locked.com/unlock",
        "http://spotify-premium-expired.net/renew",
        "https://adobe-subscription-update.com/billing",
        "http://walmart-order-confirmation.net/track",
        "https://bestbuy-purchase-alert.com/review",
        "http://target-redcard-update.net/verify",
        "https://coinbase-wallet-verify.com/confirm",
        "http://binance-security-alert.net/update",
        "https://metamask-wallet-locked.com/unlock",
        "http://blockchain-verify-identity.net/confirm",
        "https://microsoft365-renewal.com/update-payment",
        "http://zoom-meeting-expired.net/rejoin",
        "https://slack-workspace-suspended.com/verify",
        "http://github-security-alert.net/confirm",
        "https://gitlab-account-locked.com/unlock",
        "http://bitly.com.verify-link.net/redirect",
        "https://tinyurl.com-security.net/check",
        "http://googledrive-share-document.net/view",
        "https://onedrive-file-shared.com/download",
        "http://icloud-storage-full.net/upgrade",
    ]
    legitimate_urls = [
        "https://www.google.com/search",
        "https://github.com/user/repository",
        "https://stackoverflow.com/questions/12345",
        "https://www.amazon.com/product/B08N5WRWNW",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.linkedin.com/in/username",
        "https://www.facebook.com/profile",
        "https://twitter.com/username/status/123456",
        "https://www.reddit.com/r/programming",
        "https://medium.com/@author/article-title",
        "https://www.wikipedia.org/wiki/Article",
        "https://docs.python.org/3/library/",
        "https://www.npmjs.com/package/express",
        "https://pypi.org/project/flask/",
        "https://www.w3schools.com/html/",
        "https://developer.mozilla.org/en-US/docs/Web",
        "https://www.coursera.org/learn/machine-learning",
        "https://www.udemy.com/course/python-bootcamp/",
        "https://www.netflix.com/browse",
        "https://www.spotify.com/us/",
        "https://www.dropbox.com/home",
        "https://drive.google.com/drive/my-drive",
        "https://www.office.com/",
        "https://mail.google.com/mail/u/0/",
        "https://outlook.live.com/mail/",
        "https://www.instagram.com/explore/",
        "https://www.pinterest.com/",
        "https://www.tumblr.com/dashboard",
        "https://www.twitch.tv/directory",
        "https://www.discord.com/channels/",
        "https://slack.com/workspace/",
        "https://zoom.us/meeting/",
        "https://www.canva.com/design/",
        "https://www.figma.com/files/recent",
        "https://trello.com/boards/",
        "https://www.notion.so/workspace/",
        "https://www.atlassian.com/software/jira",
        "https://www.salesforce.com/",
        "https://www.shopify.com/admin",
        "https://wordpress.com/posts/",
    ]
    urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    return urls, labels

def train_model():
    print("Creating training dataset...")
    urls, labels = create_training_data()
    print(f"Total samples: {len(urls)}")
    print(f"Phishing URLs: {sum(labels)}")
    print(f"Legitimate URLs: {len(labels) - sum(labels)}")
    print("\nExtracting features from URLs...")
    features = [extract_url_features(url) for url in urls]
    X = np.array(features)
    y = np.array(labels)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    model.fit(X_train_scaled, y_train)
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    feature_names = [
        'URL Length', 'Dot Count', 'Dash Count', 'Underscore Count', 
        'Slash Count', 'Question Count', 'Equal Count', 'At Count', 
        'Ampersand Count', 'HTTPS', 'Has IP', 'Suspicious Keywords', 
        'Domain Length', 'Multiple Slashes', 'Many Dashes'
    ]
    feature_importance = sorted(
        zip(feature_names, model.feature_importances_), 
        key=lambda x: x[1], 
        reverse=True
    )
    print("\nTop 5 Important Features:")
    for name, importance in feature_importance[:5]:
        print(f"  {name}: {importance:.4f}")
    os.makedirs('models', exist_ok=True)
    print("\nSaving model and scaler...")
    joblib.dump(model, 'models/url_model.pkl')
    joblib.dump(scaler, 'models/url_scaler.pkl')
    print("✓ URL phishing detection model saved successfully!")
    print("  - models/url_model.pkl")
    print("  - models/url_scaler.pkl")

if __name__ == "__main__":
    train_model()
