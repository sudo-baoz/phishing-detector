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


import numpy as np
import pandas as pd
import joblib
import math
import re
from urllib.parse import urlparse
from collections import Counter
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')


def calculate_entropy(text):
    """
    Calculate Shannon Entropy to detect random strings
    High entropy = random/suspicious domain (e.g., asdfg123xyz.com)
    Low entropy = legitimate domain (e.g., google.com)
    
    Args:
        text: String to calculate entropy for
        
    Returns:
        float: Shannon entropy value
    """
    if not text:
        return 0.0
    
    # Count character frequency
    counter = Counter(text)
    length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def extract_features(url):
    """
    Extract 18 advanced features from URL for phishing detection
    
    Features:
    1. url_length - Total URL length
    2. dot_count - Number of '.' in URL
    3. at_count - Number of '@' in URL (credential phishing)
    4. dash_count - Number of '-' in URL
    5. double_slash_count - Number of '//' in URL
    6. has_https - Binary: HTTPS present (1) or not (0)
    7. domain_entropy - Shannon entropy of domain
    8. suspicious_word_count - Count of suspicious keywords
    9. digit_count - Total digits in URL
    10. letter_count - Total letters in URL
    11. digit_ratio - Ratio of digits to letters
    12. subdomain_count - Number of subdomains
    13. has_ip - Binary: IP address instead of domain
    14. special_char_count - Count of special characters
    15. path_length - Length of URL path
    16. has_port - Binary: Custom port present
    17. query_length - Length of query parameters
    18. tld_suspicious - Binary: Suspicious TLD (.tk, .ml, .xyz, etc.)
    
    Args:
        url: URL string to extract features from
        
    Returns:
        list: 18 feature values
    """
    try:
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Feature 1: URL length
        url_length = len(url)
        
        # Feature 2-5: Character counts
        dot_count = url.count('.')
        at_count = url.count('@')
        dash_count = url.count('-')
        double_slash_count = url.count('//')
        
        # Feature 6: HTTPS presence
        has_https = 1 if url.startswith('https://') else 0
        
        # Feature 7: Domain entropy (detect random strings)
        domain_entropy = calculate_entropy(domain) if domain else 0.0
        
        # Feature 8: Suspicious word count
        suspicious_words = ['login', 'verify', 'update', 'banking', 'secure', 
                           'account', 'signin', 'confirm', 'suspend', 'password']
        url_lower = url.lower()
        suspicious_word_count = sum(1 for word in suspicious_words if word in url_lower)
        
        # Feature 9-11: Digit and letter analysis
        digit_count = sum(c.isdigit() for c in url)
        letter_count = sum(c.isalpha() for c in url)
        # Handle division by zero
        digit_ratio = digit_count / letter_count if letter_count > 0 else 0.0
        
        # Feature 12: Subdomain count
        subdomain_count = domain.count('.') if domain else 0
        
        # Feature 13: IP address usage
        has_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0
        
        # Feature 14: Special character count
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '=', '+', '[', ']', '{', '}']
        special_char_count = sum(url.count(char) for char in special_chars)
        
        # Feature 15: Path length
        path_length = len(path)
        
        # Feature 16: Custom port
        has_port = 1 if ':' in domain and not domain.endswith(':443') and not domain.endswith(':80') else 0
        
        # Feature 17: Query length
        query_length = len(query)
        
        # Feature 18: Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.club', '.work', '.click']
        tld_suspicious = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
        
        return [
            url_length, dot_count, at_count, dash_count, double_slash_count,
            has_https, domain_entropy, suspicious_word_count, digit_count, letter_count,
            digit_ratio, subdomain_count, has_ip, special_char_count, path_length,
            has_port, query_length, tld_suspicious
        ]
        
    except Exception as e:
        print(f"Error extracting features from {url}: {e}")
        # Return zeros if extraction fails
        return [0] * 18


def generate_dummy_data(n_samples=500):
    """
    Generate realistic dummy data for phishing detection training
    
    Args:
        n_samples: Total number of samples (will be split 50/50 phishing/safe)
        
    Returns:
        tuple: (X, y) where X is feature matrix and y is labels
    """
    n_phishing = n_samples // 2
    n_safe = n_samples // 2
    
    # Phishing URL patterns (exactly n_phishing samples)
    phishing_urls = []
    
    # Pattern 1: Brand impersonation with suspicious TLDs (45 samples)
    brands = ['paypal', 'facebook', 'google', 'amazon', 'microsoft', 'apple', 'netflix', 'instagram']
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.club']
    for _ in range(45):
        brand = np.random.choice(brands)
        tld = np.random.choice(suspicious_tlds)
        subdomain = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789')) for _ in range(8))
        phishing_urls.append(f"http://{brand}-{subdomain}{tld}/login")
    
    # Pattern 2: URLs with @ symbol (25 samples)
    for _ in range(25):
        brand = np.random.choice(brands)
        evil_domain = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz')) for _ in range(10))
        phishing_urls.append(f"https://{brand}.com@{evil_domain}.com/verify")
    
    # Pattern 3: IP address usage (25 samples)
    for _ in range(25):
        ip = f"{np.random.randint(1, 255)}.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}"
        path = np.random.choice(['login', 'secure', 'banking', 'account', 'signin'])
        phishing_urls.append(f"http://{ip}/{path}.html")
    
    # Pattern 4: Excessive subdomains (25 samples)
    for _ in range(25):
        brand = np.random.choice(brands)
        subdomains = '.'.join([''.join(np.random.choice(list('abcdefgh')) for _ in range(4)) for _ in range(4)])
        phishing_urls.append(f"http://{subdomains}.{brand}-verify.com/update")
    
    # Pattern 5: High entropy domains (35 samples)
    for _ in range(35):
        random_domain = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789')) for _ in range(15))
        phishing_urls.append(f"http://{random_domain}.com/secure/login.php")
    
    # Pattern 6: Suspicious keywords with long paths (35 samples)
    for _ in range(35):
        domain = ''.join(np.random.choice(list('abcdefghijklm')) for _ in range(8))
        keywords = ['verify', 'update', 'confirm', 'suspend', 'security', 'password']
        path = '/'.join(np.random.choice(keywords) for _ in range(3))
        phishing_urls.append(f"http://{domain}.net/{path}?id={''.join(np.random.choice(list('0123456789')) for _ in range(10))}")
    
    # Pattern 7: Mix of special characters (30 samples)
    for _ in range(30):
        brand = np.random.choice(brands)
        special = ''.join(np.random.choice(['-', '_', '~']) for _ in range(3))
        phishing_urls.append(f"http://{brand}{special}secure.tk/banking?session={''.join(np.random.choice(list('abcdef0123456789')) for _ in range(20))}")
    
    # Pattern 8: Mixed patterns (30 samples to reach exactly n_phishing)
    for _ in range(30):
        brand = np.random.choice(brands)
        random_part = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789-')) for _ in range(12))
        tld = np.random.choice(['.com', '.net', '.tk', '.xyz', '.top'])
        path = np.random.choice(['login', 'verify', 'secure', 'account', 'update', 'confirm'])
        phishing_urls.append(f"http://{random_part}-{brand}{tld}/{path}")
    
    # Ensure exactly n_phishing samples
    phishing_urls = phishing_urls[:n_phishing]
    
    # Safe URL patterns (exactly n_safe samples)
    safe_urls = []
    
    # Pattern 1: Major legitimate websites (90 samples)
    legitimate_domains = [
        'https://www.google.com', 'https://www.facebook.com', 'https://www.youtube.com',
        'https://www.twitter.com', 'https://www.linkedin.com', 'https://www.instagram.com',
        'https://www.amazon.com', 'https://www.microsoft.com', 'https://www.apple.com',
        'https://www.netflix.com', 'https://www.paypal.com', 'https://www.ebay.com',
        'https://www.github.com', 'https://www.stackoverflow.com', 'https://www.wikipedia.org',
        'https://www.reddit.com', 'https://www.bbc.com', 'https://www.cnn.com',
        'https://www.nytimes.com', 'https://www.medium.com'
    ]
    
    for _ in range(90):
        domain = np.random.choice(legitimate_domains)
        paths = ['', '/search', '/about', '/contact', '/blog', '/news', '/products', '/services']
        path = np.random.choice(paths)
        safe_urls.append(f"{domain}{path}")
    
    # Pattern 2: Educational and government sites (35 samples)
    edu_gov = ['harvard.edu', 'stanford.edu', 'mit.edu', 'ox.ac.uk', 'cambridge.ac.uk', 
               'gov.uk', 'usa.gov', 'nih.gov', 'nasa.gov']
    for _ in range(35):
        domain = np.random.choice(edu_gov)
        path = np.random.choice(['', '/research', '/about', '/contact', '/news'])
        safe_urls.append(f"https://www.{domain}{path}")
    
    # Pattern 3: Well-known news and media (35 samples)
    news_sites = ['bbc.co.uk', 'reuters.com', 'theguardian.com', 'wsj.com', 'forbes.com',
                  'bloomberg.com', 'techcrunch.com', 'wired.com', 'arstechnica.com']
    for _ in range(35):
        domain = np.random.choice(news_sites)
        article = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz-')) for _ in range(20))
        safe_urls.append(f"https://www.{domain}/article/{article}")
    
    # Pattern 4: Popular forums and communities (30 samples)
    forum_sites = ['reddit.com', 'stackoverflow.com', 'stackexchange.com', 'quora.com',
                   'medium.com', 'dev.to', 'hackernews.com']
    for _ in range(30):
        domain = np.random.choice(forum_sites)
        topic = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz-')) for _ in range(15))
        safe_urls.append(f"https://www.{domain}/topic/{topic}")
    
    # Pattern 5: Cloud services and tools (25 samples)
    cloud_services = ['aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
                     'dropbox.com', 'drive.google.com', 'onedrive.com', 'icloud.com']
    for _ in range(25):
        domain = np.random.choice(cloud_services)
        safe_urls.append(f"https://{domain}/dashboard")
    
    # Pattern 6: E-commerce with proper structure (35 samples to reach exactly n_safe)
    ecommerce = ['amazon.com', 'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com']
    for _ in range(35):
        domain = np.random.choice(ecommerce)
        product_id = ''.join(np.random.choice(list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')) for _ in range(10))
        safe_urls.append(f"https://www.{domain}/product/{product_id}")
    
    # Ensure exactly n_safe samples
    safe_urls = safe_urls[:n_safe]
    
    # Create dataset
    all_urls = phishing_urls + safe_urls
    labels = [1] * len(phishing_urls) + [0] * len(safe_urls)  # 1 = phishing, 0 = safe
    
    # Verify counts match
    assert len(all_urls) == len(labels) == n_samples, f"URL count mismatch: {len(all_urls)} URLs, {len(labels)} labels, expected {n_samples}"
    
    # Extract features
    print(f"Extracting features from {len(all_urls)} URLs...")
    X = []
    for i, url in enumerate(all_urls):
        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(all_urls)} URLs")
        features = extract_features(url)
        X.append(features)
    
    return np.array(X), np.array(labels)


def train_advanced_model():
    """
    Train advanced XGBoost model with hyperparameter tuning
    """
    print("=" * 80)
    print("ADVANCED PHISHING DETECTION MODEL TRAINING")
    print("Using XGBoost with RandomizedSearchCV")
    print("=" * 80)
    print()
    
    # Generate data
    print("[1/6] Generating realistic training data...")
    X, y = generate_dummy_data(n_samples=500)
    print(f"✓ Generated {len(X)} samples ({sum(y)} phishing, {len(y) - sum(y)} safe)")
    print()
    
    # Create feature names
    feature_names = [
        'url_length', 'dot_count', 'at_count', 'dash_count', 'double_slash_count',
        'has_https', 'domain_entropy', 'suspicious_word_count', 'digit_count', 'letter_count',
        'digit_ratio', 'subdomain_count', 'has_ip', 'special_char_count', 'path_length',
        'has_port', 'query_length', 'tld_suspicious'
    ]
    
    # Split data
    print("[2/6] Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"✓ Train: {len(X_train)} samples, Test: {len(X_test)} samples")
    print()
    
    # Scale features
    print("[3/6] Scaling features with StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("✓ Features normalized")
    print()
    
    # Define hyperparameter grid
    print("[4/6] Setting up RandomizedSearchCV for hyperparameter tuning...")
    param_distributions = {
        'max_depth': [3, 5, 7, 9, 11],
        'learning_rate': [0.01, 0.05, 0.1, 0.15, 0.2],
        'n_estimators': [100, 200, 300, 400, 500],
        'min_child_weight': [1, 3, 5],
        'gamma': [0, 0.1, 0.2, 0.3],
        'subsample': [0.7, 0.8, 0.9, 1.0],
        'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
        'reg_alpha': [0, 0.1, 0.5, 1.0],
        'reg_lambda': [0.5, 1.0, 1.5, 2.0]
    }
    
    # Initialize XGBoost classifier
    xgb_model = xgb.XGBClassifier(
        objective='binary:logistic',
        random_state=42,
        eval_metric='logloss',
        use_label_encoder=False
    )
    
    # RandomizedSearchCV
    random_search = RandomizedSearchCV(
        estimator=xgb_model,
        param_distributions=param_distributions,
        n_iter=50,  # Number of parameter settings sampled
        scoring='f1',
        cv=5,  # 5-fold cross-validation
        verbose=1,
        random_state=42,
        n_jobs=-1  # Use all CPU cores
    )
    
    print(f"✓ RandomizedSearchCV configured")
    print(f"  - Testing 50 random parameter combinations")
    print(f"  - 5-fold cross-validation")
    print(f"  - Optimizing for F1 score")
    print()
    
    # Train model
    print("[5/6] Training XGBoost model (this may take a few minutes)...")
    print("-" * 80)
    random_search.fit(X_train_scaled, y_train)
    print("-" * 80)
    print("✓ Training complete!")
    print()
    
    # Best parameters
    print("=" * 80)
    print("BEST HYPERPARAMETERS FOUND:")
    print("=" * 80)
    for param, value in random_search.best_params_.items():
        print(f"  {param:20s}: {value}")
    print()
    print(f"Best CV F1 Score: {random_search.best_score_:.4f}")
    print()
    
    # Evaluate on test set
    print("[6/6] Evaluating model on test set...")
    best_model = random_search.best_estimator_
    y_pred = best_model.predict(X_test_scaled)
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy:.4f}")
    print()
    
    print("=" * 80)
    print("CLASSIFICATION REPORT:")
    print("=" * 80)
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    
    print("=" * 80)
    print("CONFUSION MATRIX:")
    print("=" * 80)
    cm = confusion_matrix(y_test, y_pred)
    print(f"                Predicted Safe  Predicted Phishing")
    print(f"Actual Safe         {cm[0][0]:4d}            {cm[0][1]:4d}")
    print(f"Actual Phishing     {cm[1][0]:4d}            {cm[1][1]:4d}")
    print()
    
    # Feature importance
    print("=" * 80)
    print("TOP 10 MOST IMPORTANT FEATURES:")
    print("=" * 80)
    feature_importance = best_model.feature_importances_
    importance_df = pd.DataFrame({
        'Feature': feature_names,
        'Importance': feature_importance
    }).sort_values('Importance', ascending=False)
    
    for i, row in importance_df.head(10).iterrows():
        print(f"  {i+1:2d}. {row['Feature']:25s}: {row['Importance']:.4f}")
    print()
    
    # Save model
    print("=" * 80)
    print("SAVING MODEL:")
    print("=" * 80)
    model_package = {
        'model': best_model,
        'scaler': scaler,
        'feature_names': feature_names,
        'best_params': random_search.best_params_,
        'cv_score': random_search.best_score_,
        'test_accuracy': accuracy
    }
    
    joblib.dump(model_package, 'advanced_model.pkl')
    print("✓ Model saved to: advanced_model.pkl")
    print("  Package includes:")
    print("    - Best XGBoost model")
    print("    - StandardScaler")
    print("    - Feature names")
    print("    - Best hyperparameters")
    print("    - Performance metrics")
    print()
    
    print("=" * 80)
    print("TRAINING COMPLETE!")
    print("=" * 80)
    print(f"Final Test Accuracy: {accuracy:.2%}")
    print("Model ready for deployment!")
    print()


if __name__ == "__main__":
    train_advanced_model()
