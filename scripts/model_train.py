"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

"""
Machine Learning Model Training Script for Phishing URL Detection
Trains a RandomForest classifier and saves the model with scaler for production use
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import re
from urllib.parse import urlparse


def generate_dummy_data():
    """
    Generate synthetic dataset for testing the ML pipeline
    Returns: pandas DataFrame with 200 samples (100 safe, 100 phishing)
    """
    
    # Safe URLs (legitimate websites)
    safe_urls = [
        'https://www.google.com/search?q=python',
        'https://www.facebook.com/profile',
        'https://github.com/trending',
        'https://stackoverflow.com/questions',
        'https://www.amazon.com/products',
        'https://www.youtube.com/watch',
        'https://www.linkedin.com/in/profile',
        'https://www.microsoft.com/en-us',
        'https://www.apple.com/iphone',
        'https://www.netflix.com/browse',
        'https://twitter.com/home',
        'https://www.reddit.com/r/python',
        'https://www.wikipedia.org/wiki/Main',
        'https://www.bbc.com/news',
        'https://www.cnn.com/world',
        'hutech.edu.vn',
        'https://hutech.edu.vn/students',
        'https://www.coursera.org/courses',
        'https://www.udemy.com/course/python',
        'https://www.edx.org/learn/programming',
        'https://www.mozilla.org/firefox',
        'https://www.python.org/downloads',
        'https://docs.python.org/3/',
        'https://www.djangoproject.com/',
        'https://reactjs.org/docs',
        'https://nodejs.org/en/docs',
        'https://www.postgresql.org/',
        'https://www.mysql.com/',
        'https://www.oracle.com/database',
        'https://aws.amazon.com/console',
        'https://cloud.google.com/',
        'https://azure.microsoft.com/',
        'https://www.digitalocean.com/',
        'https://www.heroku.com/home',
        'https://www.dropbox.com/home',
        'https://drive.google.com/drive',
        'https://www.paypal.com/myaccount',
        'https://www.ebay.com/shop',
        'https://www.alibaba.com/trade',
        'https://www.walmart.com/browse',
        'https://www.bestbuy.com/site',
        'https://www.target.com/c',
        'https://www.ikea.com/us',
        'https://www.nike.com/w',
        'https://www.adidas.com/us',
        'https://www.zara.com/us',
        'https://www.hm.com/us',
        'https://www.uniqlo.com/us',
        'https://store.steampowered.com/',
        'https://www.epicgames.com/store',
    ]
    
    # Phishing URLs (suspicious/malicious patterns)
    phishing_urls = [
        'http://secure-login-bank.xyz/verify',
        'https://paypal-security-check.com/account',
        'http://amazon-prime-renew.tk/payment',
        'https://apple-id-unlock.ml/signin',
        'http://netflix-billing-update.ga/verify',
        'https://microsoft-security-alert.cf/update',
        'http://facebook-verify-account.tk/login',
        'https://google-account-recovery.ml/reset',
        'http://instagram-support-team.ga/verify',
        'https://twitter-verification-badge.tk/apply',
        'http://linkedin-premium-free.ml/signup',
        'https://amazon-gift-card-1000.xyz/claim',
        'http://paypal-money-received.tk/accept',
        'https://bank-security-department.ga/urgent',
        'http://credit-card-approved.ml/activate',
        'https://irs-tax-refund-pending.tk/claim',
        'http://usps-package-delivery.ga/track',
        'https://fedex-shipment-update.ml/view',
        'http://dhl-express-delivery.tk/confirm',
        'https://ups-tracking-failed.ga/retry',
        'http://www-paypal-com-login.tk',
        'https://secure-amazon-signin.ml',
        'http://apple-support-case.ga',
        'https://microsoft-windows-update.tk',
        'http://google-ads-payment.ml',
        'https://facebook-copyright-notice.ga',
        'http://instagram-blue-tick.tk',
        'https://twitter-monetization.ml',
        'http://youtube-partner-program.ga',
        'https://tiktok-verification-official.tk',
        'http://whatsapp-web-login.ml',
        'https://telegram-premium-free.ga',
        'http://zoom-meeting-security.tk',
        'https://skype-account-verify.ml',
        'http://discord-nitro-gift.ga',
        'https://spotify-premium-generator.tk',
        'http://netflix-account-share.ml',
        'https://hulu-free-trial-extended.ga',
        'http://disney-plus-lifetime.tk',
        'https://hbo-max-promo-code.ml',
        'http://steam-wallet-code.ga',
        'https://playstation-plus-free.tk',
        'http://xbox-game-pass-ultimate.ml',
        'https://nintendo-eshop-card.ga',
        'http://roblox-free-robux.tk',
        'https://fortnite-vbucks-generator.ml',
        'http://minecraft-premium-account.ga',
        'https://pubg-uc-giveaway.tk',
        'http://free-fire-diamonds-hack.ml',
        'https://mobile-legends-cheat.ga',
    ]
    
    # Generate more samples by adding variations
    safe_variations = []
    for url in safe_urls[:20]:
        safe_variations.extend([
            url + '/page1',
            url + '?id=123',
            url + '#section',
            url.replace('https://', 'http://') if 'https' in url else url,
            url + '/search?q=test',
        ])
    
    phishing_variations = []
    for url in phishing_urls[:20]:
        phishing_variations.extend([
            url + '?token=abc123',
            url + '&session=xyz',
            url + '/confirm.php',
            url + '?user=admin',
            url + '/secure/login',
        ])
    
    # Combine to get exactly 100 of each
    all_safe = (safe_urls + safe_variations)[:100]
    all_phishing = (phishing_urls + phishing_variations)[:100]
    
    # Create DataFrame
    data = {
        'url': all_safe + all_phishing,
        'label': [0] * 100 + [1] * 100  # 0 = safe, 1 = phishing
    }
    
    df = pd.DataFrame(data)
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Generated {len(df)} samples:")
    print(f"  - Safe URLs: {(df['label'] == 0).sum()}")
    print(f"  - Phishing URLs: {(df['label'] == 1).sum()}")
    
    return df


def extract_features(url):
    """
    Extract numerical features from a URL for ML model
    
    Args:
        url (str): URL to extract features from
        
    Returns:
        dict: Dictionary of feature values
    """
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except:
        parsed = None
    
    # Feature 1: URL Length
    url_length = len(url)
    
    # Feature 2: Dot count
    dot_count = url.count('.')
    
    # Feature 3: Has @ symbol (often used in phishing)
    has_at_symbol = 1 if '@' in url else 0
    
    # Feature 4: Is HTTPS
    is_https = 1 if url.startswith('https://') else 0
    
    # Feature 5: Digit count
    digit_count = sum(c.isdigit() for c in url)
    
    # Additional features for better accuracy
    # Feature 6: Hyphen count (phishing URLs often have many hyphens)
    hyphen_count = url.count('-')
    
    # Feature 7: Underscore count
    underscore_count = url.count('_')
    
    # Feature 8: Slash count
    slash_count = url.count('/')
    
    # Feature 9: Question mark count (query parameters)
    question_count = url.count('?')
    
    # Feature 10: Ampersand count
    ampersand_count = url.count('&')
    
    # Feature 11: Domain length
    domain_length = len(parsed.netloc) if parsed else 0
    
    # Feature 12: Has suspicious TLD (.tk, .ml, .ga, .cf, .xyz)
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq']
    has_suspicious_tld = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
    
    return {
        'url_length': url_length,
        'dot_count': dot_count,
        'has_at_symbol': has_at_symbol,
        'is_https': is_https,
        'digit_count': digit_count,
        'hyphen_count': hyphen_count,
        'underscore_count': underscore_count,
        'slash_count': slash_count,
        'question_count': question_count,
        'ampersand_count': ampersand_count,
        'domain_length': domain_length,
        'has_suspicious_tld': has_suspicious_tld,
    }


def train_model(df):
    """
    Train RandomForest classifier on the dataset
    
    Args:
        df (DataFrame): Dataset with 'url' and 'label' columns
        
    Returns:
        tuple: (trained_model, scaler, X_test, y_test)
    """
    
    print("\n" + "=" * 60)
    print("FEATURE EXTRACTION")
    print("=" * 60)
    
    # Extract features for all URLs
    features_list = []
    for url in df['url']:
        features = extract_features(url)
        features_list.append(features)
    
    # Convert to DataFrame
    X = pd.DataFrame(features_list)
    y = df['label']
    
    print(f"Extracted {len(X.columns)} features:")
    for col in X.columns:
        print(f"  - {col}")
    
    print(f"\nFeature statistics:")
    print(X.describe())
    
    # Split data
    print("\n" + "=" * 60)
    print("DATA SPLITTING")
    print("=" * 60)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Testing set: {len(X_test)} samples")
    print(f"Train - Safe: {(y_train == 0).sum()}, Phishing: {(y_train == 1).sum()}")
    print(f"Test - Safe: {(y_test == 0).sum()}, Phishing: {(y_test == 1).sum()}")
    
    # Standardize features
    print("\n" + "=" * 60)
    print("FEATURE SCALING")
    print("=" * 60)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Applied StandardScaler to features")
    print(f"Feature means: {scaler.mean_}")
    print(f"Feature std: {scaler.scale_}")
    
    # Train model
    print("\n" + "=" * 60)
    print("MODEL TRAINING")
    print("=" * 60)
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    print("Training RandomForestClassifier...")
    model.fit(X_train_scaled, y_train)
    print("✓ Training completed!")
    
    # Feature importance
    print("\nFeature Importance:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print(feature_importance.to_string(index=False))
    
    return model, scaler, X_test_scaled, y_test, X.columns.tolist()


def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance and print metrics
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels
    """
    
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy * 100:.2f}%")
    
    # Classification Report
    print("\nClassification Report:")
    print("-" * 60)
    print(classification_report(
        y_test, 
        y_pred, 
        target_names=['Safe', 'Phishing'],
        digits=4
    ))
    
    # Confusion Matrix
    print("Confusion Matrix:")
    print("-" * 60)
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted")
    print(f"                 Safe  Phishing")
    print(f"Actual Safe      {cm[0][0]:4d}  {cm[0][1]:4d}")
    print(f"       Phishing  {cm[1][0]:4d}  {cm[1][1]:4d}")
    
    return accuracy


def save_model(model, scaler, feature_names, filename='phishing_model.pkl'):
    """
    Save trained model, scaler, and feature names to a single file
    
    Args:
        model: Trained model
        scaler: Fitted StandardScaler
        feature_names: List of feature names
        filename: Output filename
    """
    
    print("\n" + "=" * 60)
    print("SAVING MODEL")
    print("=" * 60)
    
    # Package everything together
    model_package = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names,
        'version': '1.0.0',
        'trained_date': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Save to file
    joblib.dump(model_package, filename)
    
    print(f"✓ Model saved to: {filename}")
    print(f"  - Model: RandomForestClassifier")
    print(f"  - Scaler: StandardScaler")
    print(f"  - Features: {len(feature_names)}")
    print(f"  - Version: {model_package['version']}")
    print(f"  - Trained: {model_package['trained_date']}")


def main():
    """Main training pipeline"""
    
    print("=" * 60)
    print("PHISHING URL DETECTION - MODEL TRAINING")
    print("=" * 60)
    
    # Step 1: Generate or load data
    print("\nStep 1: Loading Data...")
    df = generate_dummy_data()
    
    # Step 2: Train model
    print("\nStep 2: Training Model...")
    model, scaler, X_test, y_test, feature_names = train_model(df)
    
    # Step 3: Evaluate model
    print("\nStep 3: Evaluating Model...")
    accuracy = evaluate_model(model, X_test, y_test)
    
    # Step 4: Save model
    print("\nStep 4: Saving Model...")
    save_model(model, scaler, feature_names)
    
    # Summary
    print("\n" + "=" * 60)
    print("TRAINING COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print(f"✓ Model accuracy: {accuracy * 100:.2f}%")
    print(f"✓ Model file: phishing_model.pkl")
    print(f"✓ Ready for production use!")
    print("\nNext steps:")
    print("1. Integrate model into FastAPI endpoint")
    print("2. Test with real URLs")
    print("3. Collect more data to improve accuracy")
    print("=" * 60)


if __name__ == "__main__":
    main()
