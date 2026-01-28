# codes by vision
import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

def create_training_data():
    phishing_emails = [
        "URGENT: Your account will be suspended. Click here to verify your identity immediately.",
        "Congratulations! You've won $1,000,000. Click this link to claim your prize now!",
        "Your PayPal account has been limited. Please update your information to restore access.",
        "Security Alert: Unusual activity detected. Verify your account within 24 hours.",
        "Your package could not be delivered. Click here to reschedule delivery.",
        "Your password will expire today. Reset it now to avoid account suspension.",
        "You have received a secure message. Click here to view it now.",
        "Your bank account has been compromised. Verify your identity immediately.",
        "IRS Tax Refund: You are eligible for a refund. Click to claim $500.",
        "Your Netflix subscription has expired. Update payment information now.",
        "Amazon: Your order #12345 has been cancelled. Click to review.",
        "Microsoft Security: Your computer is infected. Download our tool now.",
        "Verify your email address to continue using our service.",
        "Your credit card has been charged $999. If this wasn't you, click here.",
        "Urgent: Your account will be deleted in 24 hours. Confirm your identity.",
        "You have a pending invoice. Click here to view and pay immediately.",
        "Your social security number has been suspended. Call us immediately.",
        "Confirm your shipping address for your recent purchase.",
        "Your Apple ID has been locked. Reset your password now.",
        "Final notice: Your account is overdue. Pay now to avoid penalties.",
        "You've been selected for a special offer. Click here to redeem.",
        "Your Google account login from unknown device. Verify now.",
        "Your cryptocurrency wallet requires verification. Click here.",
        "Urgent security update required. Download now to protect your data.",
        "Your refund is ready. Enter your bank details to receive payment.",
        "Congratulations! You've been selected for a free iPhone. Claim now.",
        "Your email storage is full. Upgrade now to avoid losing emails.",
        "Verify your identity to unlock your account immediately.",
        "Your package is waiting at customs. Pay fees to release shipment.",
        "Your subscription payment failed. Update billing information now.",
        "Click here to confirm you are not a robot and verify your account.",
        "Your account has been hacked. Change your password immediately.",
        "You have unclaimed money waiting. Click to claim your funds.",
        "Your computer warranty has expired. Renew now for protection.",
        "Urgent: Confirm your email or lose access to your account.",
        "Your tax return has been rejected. Click here to resubmit.",
        "You have a new secure message from your bank. View now.",
        "Your Facebook account will be disabled. Verify your identity.",
        "Your lottery ticket has won! Claim your prize before it expires.",
        "Your antivirus subscription has expired. Renew immediately.",
    ]
    legitimate_emails = [
        "Hi team, please review the attached quarterly report by Friday.",
        "Thank you for your order. Your tracking number is 123456789.",
        "Meeting scheduled for tomorrow at 2 PM in conference room B.",
        "Your monthly statement is now available in your account dashboard.",
        "Welcome to our newsletter! Here are this week's top articles.",
        "Your appointment has been confirmed for January 15th at 10 AM.",
        "Thank you for subscribing. You can manage preferences in settings.",
        "Your order has shipped and will arrive in 3-5 business days.",
        "Reminder: Your subscription renews on the 1st of next month.",
        "Here's your receipt for your recent purchase. Thank you!",
        "Your support ticket #456 has been resolved. Please review.",
        "New features have been added to your account. Check them out!",
        "Your weekly digest: Top stories from your favorite categories.",
        "Thank you for attending our webinar. Here's the recording link.",
        "Your profile has been successfully updated. Review changes anytime.",
        "Invitation: Join us for our annual conference next month.",
        "Your feedback helps us improve. Take our 2-minute survey.",
        "New comment on your post: Check out what others are saying.",
        "Your report is ready for download in your account dashboard.",
        "Reminder: Complete your profile to get personalized recommendations.",
        "Your connection request has been accepted. Start networking!",
        "Here are some products you might like based on your interests.",
        "Your course enrollment is confirmed. Classes begin next week.",
        "Thank you for your payment. Your account is now up to date.",
        "Your document has been shared with the team successfully.",
        "New message from your colleague. Reply directly from your inbox.",
        "Your project milestone has been completed. Great work team!",
        "Monthly summary: Here's what happened in your account this month.",
        "Your reservation is confirmed. We look forward to seeing you.",
        "New update available for your application. Install at your convenience.",
        "Your question has been answered by our community. View response.",
        "Congratulations on completing the course! Download your certificate.",
        "Your settings have been saved successfully. Changes are now active.",
        "Weekly roundup: Articles and updates from your subscriptions.",
        "Your event registration is complete. Add to your calendar.",
        "Thank you for your review. It helps other customers make decisions.",
        "Your download is ready. The file will be available for 7 days.",
        "Reminder: Your upcoming appointment is in 2 days.",
        "Your team has been mentioned in a new discussion thread.",
        "Your backup completed successfully. All files are secure.",
    ]
    emails = phishing_emails + legitimate_emails
    labels = [1] * len(phishing_emails) + [0] * len(legitimate_emails)
    return emails, labels

def train_model():
    print("Creating training dataset...")
    emails, labels = create_training_data()
    print(f"Total samples: {len(emails)}")
    print(f"Phishing emails: {sum(labels)}")
    print(f"Legitimate emails: {len(labels) - sum(labels)}")
    X_train, X_test, y_train, y_test = train_test_split(
        emails, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print("\nTraining TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    print("Training Logistic Regression model...")
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train_tfidf, y_train)
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    os.makedirs('models', exist_ok=True)
    print("\nSaving model and vectorizer...")
    joblib.dump(model, 'models/email_model.pkl')
    joblib.dump(vectorizer, 'models/email_vectorizer.pkl')
    print("✓ Email phishing detection model saved successfully!")
    print("  - models/email_model.pkl")
    print("  - models/email_vectorizer.pkl")

if __name__ == "__main__":
    train_model()
