"""
Advanced Phishing Detection Model Training Script
Features: XGBoost, Enhanced Features, SHAP Explainability, Synthetic Data Generation
"""

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
import math
from urllib.parse import urlparse
from collections import Counter
import xgboost as xgb
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, classification_report, confusion_matrix
)
import warnings
warnings.filterwarnings('ignore')

# Try to import SHAP for explainability
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("[WARNING] SHAP not installed. Install with: pip install shap")


# ==================== Feature Engineering ====================

def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text (measures randomness)
    Higher entropy = more random = more suspicious
    
    Args:
        text: String to calculate entropy for
        
    Returns:
        Shannon entropy value
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(text)
    text_length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / text_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def count_suspicious_words(url: str) -> int:
    """
    Count occurrences of suspicious keywords commonly used in phishing
    
    Args:
        url: URL string to analyze
        
    Returns:
        Count of suspicious words found
    """
    suspicious_keywords = [
        'secure', 'account', 'verify', 'update', 'login', 'signin',
        'banking', 'confirm', 'suspended', 'unusual', 'click', 'here',
        'urgent', 'immediately', 'password', 'credential', 'authentication',
        'validate', 'restore', 'limited', 'verify', 'ssn', 'social'
    ]
    
    url_lower = url.lower()
    count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    
    return count


def count_subdomains(url: str) -> int:
    """
    Count number of subdomains in URL
    Example: a.b.c.example.com has 3 subdomains
    
    Args:
        url: URL string to analyze
        
    Returns:
        Number of subdomains
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Count dots (subdomains = dots - 1 for typical domain.tld)
        dots = domain.count('.')
        
        # Adjust for known TLDs (.co.uk, .com.au, etc.)
        if domain.endswith(('.co.uk', '.com.au', '.co.za', '.co.nz')):
            return max(0, dots - 2)
        
        return max(0, dots - 1)
        
    except:
        return 0


def extract_advanced_features(url: str) -> dict:
    """
    Extract comprehensive features from URL for ML model
    Includes original features + entropy + suspicious words + subdomain count
    
    Args:
        url: URL string to extract features from
        
    Returns:
        Dictionary of feature names and values
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
    except:
        parsed = None
        domain = ""
    
    # Original features
    features = {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'has_at_symbol': 1 if '@' in url else 0,
        'is_https': 1 if url.startswith('https://') else 0,
        'digit_count': sum(c.isdigit() for c in url),
        'hyphen_count': url.count('-'),
        'underscore_count': url.count('_'),
        'slash_count': url.count('/'),
        'question_count': url.count('?'),
        'ampersand_count': url.count('&'),
        'domain_length': len(domain),
        'has_suspicious_tld': 1 if any(url.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq']) else 0,
    }
    
    # Advanced features
    features['domain_entropy'] = calculate_entropy(domain)
    features['suspicious_word_count'] = count_suspicious_words(url)
    features['subdomain_count'] = count_subdomains(url)
    
    return features


# ==================== Synthetic Data Generation ====================

def generate_legitimate_urls(n: int = 500) -> list:
    """
    Generate synthetic legitimate URLs
    
    Args:
        n: Number of URLs to generate
        
    Returns:
        List of legitimate URL strings
    """
    legitimate_domains = [
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com', 'reddit.com',
        'github.com', 'stackoverflow.com', 'microsoft.com', 'apple.com', 'adobe.com',
        'zoom.us', 'dropbox.com', 'slack.com', 'spotify.com', 'twitch.tv'
    ]
    
    paths = [
        '', '/home', '/about', '/contact', '/products', '/services', '/blog',
        '/news', '/help', '/support', '/docs', '/api', '/search', '/profile'
    ]
    
    queries = [
        '', '?q=search', '?id=123', '?page=1', '?category=tech', '?user=john'
    ]
    
    urls = []
    for _ in range(n):
        protocol = np.random.choice(['https://', 'http://'], p=[0.8, 0.2])
        domain = np.random.choice(legitimate_domains)
        path = np.random.choice(paths)
        query = np.random.choice(queries, p=[0.5, 0.1, 0.1, 0.1, 0.1, 0.1])
        
        url = f"{protocol}{domain}{path}{query}"
        urls.append(url)
    
    return urls


def generate_phishing_urls(n: int = 500) -> list:
    """
    Generate synthetic phishing URLs with common phishing patterns
    
    Args:
        n: Number of URLs to generate
        
    Returns:
        List of phishing URL strings
    """
    # Phishing characteristics
    suspicious_domains = [
        'paypal-verify', 'secure-banking', 'account-update', 'confirm-identity',
        'verify-account', 'secure-login', 'update-information', 'banking-secure',
        'amazon-confirm', 'netflix-payment', 'apple-verify', 'microsoft-account'
    ]
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.click']
    
    suspicious_paths = [
        '/login', '/signin', '/verify', '/update', '/confirm', '/secure',
        '/account/verify', '/banking/login', '/payment/update', '/security/check'
    ]
    
    suspicious_words = [
        'urgent', 'immediately', 'suspended', 'unusual', 'verify-now',
        'click-here', 'limited-time', 'act-now'
    ]
    
    urls = []
    for _ in range(n):
        # Most phishing uses http (not https)
        protocol = np.random.choice(['http://', 'https://'], p=[0.7, 0.3])
        
        # Create suspicious domain
        if np.random.random() < 0.5:
            # Use suspicious domain + suspicious TLD
            domain = np.random.choice(suspicious_domains) + np.random.choice(suspicious_tlds)
        else:
            # Use random subdomain structure (e.g., secure.login.paypal.tk)
            subdomain1 = np.random.choice(['secure', 'login', 'verify', 'account', 'www'])
            subdomain2 = np.random.choice(['paypal', 'amazon', 'bank', 'secure', 'verify'])
            tld = np.random.choice(suspicious_tlds)
            domain = f"{subdomain1}.{subdomain2}{tld}"
        
        # Add suspicious path
        path = np.random.choice(suspicious_paths)
        
        # Sometimes add @ symbol (phishing technique)
        if np.random.random() < 0.2:
            domain = f"legitimate.com@{domain}"
        
        # Sometimes add lots of hyphens or underscores
        if np.random.random() < 0.3:
            extra = np.random.choice(['-', '_']) * np.random.randint(2, 5)
            domain = domain.replace('.', extra)
        
        # Sometimes add suspicious query
        query = ''
        if np.random.random() < 0.4:
            suspicious_word = np.random.choice(suspicious_words)
            query = f"?action={suspicious_word}&id={''.join(np.random.choice(list('0123456789abcdef'), 8))}"
        
        url = f"{protocol}{domain}{path}{query}"
        urls.append(url)
    
    return urls


def generate_dataset(n_samples: int = 1000):
    """
    Generate complete synthetic dataset with features and labels
    
    Args:
        n_samples: Total number of samples to generate (split 50/50 legit/phishing)
        
    Returns:
        X (DataFrame), y (array): Features and labels
    """
    print(f"\n{'='*70}")
    print("GENERATING SYNTHETIC DATASET")
    print(f"{'='*70}")
    
    half = n_samples // 2
    
    # Generate URLs
    print(f"\nGenerating {half} legitimate URLs...")
    legitimate_urls = generate_legitimate_urls(half)
    
    print(f"Generating {half} phishing URLs...")
    phishing_urls = generate_phishing_urls(half)
    
    # Combine
    all_urls = legitimate_urls + phishing_urls
    labels = [0] * half + [1] * half  # 0 = legitimate, 1 = phishing
    
    # Extract features
    print("\nExtracting features from URLs...")
    features_list = []
    for i, url in enumerate(all_urls):
        if (i + 1) % 200 == 0:
            print(f"  Processed {i + 1}/{len(all_urls)} URLs...")
        features = extract_advanced_features(url)
        features_list.append(features)
    
    # Create DataFrame
    X = pd.DataFrame(features_list)
    y = np.array(labels)
    
    print(f"\n[OK] Dataset generated:")
    print(f"  - Total samples: {len(X)}")
    print(f"  - Features: {len(X.columns)}")
    print(f"  - Legitimate: {sum(y == 0)}")
    print(f"  - Phishing: {sum(y == 1)}")
    print(f"\nFeatures: {list(X.columns)}")
    
    return X, y


# ==================== Model Training ====================

def train_xgboost_model(X_train, y_train, X_test, y_test):
    """
    Train XGBoost classifier with optimized hyperparameters
    
    Args:
        X_train, y_train: Training data
        X_test, y_test: Test data
        
    Returns:
        Trained XGBoost model
    """
    print(f"\n{'='*70}")
    print("TRAINING XGBOOST MODEL")
    print(f"{'='*70}")
    
    # Define XGBoost parameters
    params = {
        'max_depth': 6,
        'learning_rate': 0.1,
        'n_estimators': 200,
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'random_state': 42,
        'n_jobs': -1,
        'subsample': 0.8,
        'colsample_bytree': 0.8
    }
    
    print(f"\nHyperparameters:")
    for key, value in params.items():
        print(f"  - {key}: {value}")
    
    # Train model
    print("\nTraining XGBoost classifier...")
    model = xgb.XGBClassifier(**params)
    
    # Fit with early stopping
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )
    
    print("[OK] Model training completed")
    
    return model


def evaluate_model(model, X_train, y_train, X_test, y_test, feature_names):
    """
    Evaluate model performance and display metrics
    
    Args:
        model: Trained model
        X_train, y_train: Training data
        X_test, y_test: Test data
        feature_names: List of feature names
    """
    print(f"\n{'='*70}")
    print("MODEL EVALUATION")
    print(f"{'='*70}")
    
    # Predictions
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)
    
    # Metrics
    print("\n--- Training Set ---")
    print(f"Accuracy:  {accuracy_score(y_train, y_train_pred):.4f}")
    print(f"Precision: {precision_score(y_train, y_train_pred):.4f}")
    print(f"Recall:    {recall_score(y_train, y_train_pred):.4f}")
    print(f"F1-Score:  {f1_score(y_train, y_train_pred):.4f}")
    
    print("\n--- Test Set ---")
    print(f"Accuracy:  {accuracy_score(y_test, y_test_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_test_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_test_pred):.4f}")
    print(f"F1-Score:  {f1_score(y_test, y_test_pred):.4f}")
    
    # Confusion Matrix
    print("\n--- Confusion Matrix (Test Set) ---")
    cm = confusion_matrix(y_test, y_test_pred)
    print(f"True Negatives:  {cm[0][0]}")
    print(f"False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]}")
    print(f"True Positives:  {cm[1][1]}")
    
    # Cross-validation
    print("\n--- Cross-Validation (5-fold) ---")
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
    print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Feature Importance
    print(f"\n{'='*70}")
    print("FEATURE IMPORTANCE")
    print(f"{'='*70}")
    
    importances = model.feature_importances_
    feature_importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    for idx, row in feature_importance_df.head(10).iterrows():
        print(f"  {row['feature']:25s} : {row['importance']:.4f}")
    
    return feature_importance_df


def explain_with_shap(model, X_test, feature_names):
    """
    Generate SHAP explanations for model predictions
    
    Args:
        model: Trained model
        X_test: Test data
        feature_names: List of feature names
    """
    if not SHAP_AVAILABLE:
        print("\n[SKIP] SHAP not available. Install with: pip install shap")
        return
    
    print(f"\n{'='*70}")
    print("SHAP EXPLAINABILITY ANALYSIS")
    print(f"{'='*70}")
    
    try:
        print("\nCalculating SHAP values (this may take a moment)...")
        
        # Create SHAP explainer
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_test)
        
        # Summary
        print("\nSHAP Feature Importance (mean absolute SHAP value):")
        shap_importance = np.abs(shap_values).mean(axis=0)
        shap_df = pd.DataFrame({
            'feature': feature_names,
            'shap_importance': shap_importance
        }).sort_values('shap_importance', ascending=False)
        
        for idx, row in shap_df.head(10).iterrows():
            print(f"  {row['feature']:25s} : {row['shap_importance']:.4f}")
        
        print("\n[OK] SHAP analysis completed")
        print("Note: SHAP values explain individual predictions (not saved in this script)")
        
    except Exception as e:
        print(f"\n[ERROR] SHAP analysis failed: {e}")


# ==================== Main Training Pipeline ====================

def main():
    """
    Main training pipeline
    """
    print("\n" + "="*70)
    print(" ADVANCED PHISHING DETECTION MODEL TRAINING ")
    print("="*70)
    print("\nFeatures:")
    print("  - XGBoost Classifier (Gradient Boosting)")
    print("  - 15 Advanced Features (including Entropy, Suspicious Words, Subdomains)")
    print("  - SHAP Explainability (if available)")
    print("  - Synthetic Data Generation")
    
    # Generate dataset
    X, y = generate_dataset(n_samples=2000)
    
    # Split data
    print(f"\n{'='*70}")
    print("SPLITTING DATA")
    print(f"{'='*70}")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set:     {len(X_test)} samples")
    
    # Feature names
    feature_names = list(X.columns)
    
    # Scale features
    print(f"\n{'='*70}")
    print("FEATURE SCALING")
    print(f"{'='*70}")
    print("\nStandardizing features (mean=0, std=1)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("[OK] Features scaled")
    
    # Train model
    model = train_xgboost_model(X_train_scaled, y_train, X_test_scaled, y_test)
    
    # Evaluate model
    feature_importance_df = evaluate_model(
        model, X_train_scaled, y_train, X_test_scaled, y_test, feature_names
    )
    
    # SHAP explainability
    explain_with_shap(model, X_test_scaled, feature_names)
    
    # Save model
    print(f"\n{'='*70}")
    print("SAVING MODEL")
    print(f"{'='*70}")
    
    model_dir = Path("models")
    model_dir.mkdir(exist_ok=True)
    
    model_package = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names,
        'feature_importance': feature_importance_df.to_dict('records'),
        'model_type': 'XGBClassifier',
        'n_features': len(feature_names)
    }
    
    model_path = model_dir / "phishing_model.pkl"
    joblib.dump(model_package, model_path)
    
    print(f"\n[OK] Model saved to: {model_path}")
    print(f"\nModel package contains:")
    print(f"  - XGBoost classifier")
    print(f"  - StandardScaler")
    print(f"  - Feature names ({len(feature_names)} features)")
    print(f"  - Feature importance rankings")
    
    print(f"\n{'='*70}")
    print("TRAINING COMPLETED SUCCESSFULLY")
    print(f"{'='*70}")
    print(f"\nYou can now use this model in your API!")
    print(f"The model will automatically be loaded by the PhishingPredictor service.")


if __name__ == "__main__":
    main()
