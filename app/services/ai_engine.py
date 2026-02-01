"""
AI Engine Service - Phishing Detection ML Model
Implements Singleton pattern for model loading and prediction
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any
import joblib
import pandas as pd
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class PhishingPredictor:
    """
    Singleton class for phishing detection ML model
    Loads model once and provides prediction interface
    """
    
    _instance: Optional['PhishingPredictor'] = None
    _initialized: bool = False
    
    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize predictor (only once)"""
        if not self._initialized:
            self.model = None
            self.scaler = None
            self.feature_names = None
            
            # Trusted domains whitelist - known safe websites
            self.trusted_domains = {
                'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
                'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
                'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
                'paypal.com', 'ebay.com', 'yahoo.com', 'bing.com', 'zoom.us',
                'whatsapp.com', 'telegram.org', 'discord.com', 'twitch.tv', 'tiktok.com',
                'dropbox.com', 'drive.google.com', 'office.com', 'live.com', 'outlook.com',
                'blogger.com', 'wordpress.com', 'medium.com', 'tumblr.com', 'pinterest.com',
                'shopify.com', 'stripe.com', 'square.com', 'wix.com', 'godaddy.com'
            }
            
            self._initialized = True
    
    def load_model(self, model_path: str = "models/phishing_model.pkl") -> bool:
        """
        Load trained ML model from file
        
        Args:
            model_path: Path to the pickled model file
            
        Returns:
            bool: True if successful, False otherwise
            
        Raises:
            FileNotFoundError: If model file doesn't exist
            Exception: For other loading errors
        """
        path = Path(model_path)
        
        try:
            if not path.exists():
                logger.error(f"Model file not found at {path}")
                raise FileNotFoundError(f"Model file not found: {path}")
            
            logger.info(f"Loading ML model from {path}")
            model_package = joblib.load(path)
            
            self.model = model_package['model']
            self.scaler = model_package['scaler']
            self.feature_names = model_package['feature_names']
            
            logger.info("[OK] ML Model loaded successfully")
            logger.info(f"  - Model type: {type(self.model).__name__}")
            logger.info(f"  - Features: {len(self.feature_names)}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            raise
    
    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return all([self.model is not None, self.scaler is not None, self.feature_names is not None])
    
    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text (measures randomness)
        Higher entropy = more random = more suspicious
        """
        if not text:
            return 0.0
        
        from collections import Counter
        import math
        
        char_counts = Counter(text)
        text_length = len(text)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def count_suspicious_words(self, url: str) -> int:
        """Count occurrences of suspicious keywords commonly used in phishing"""
        suspicious_keywords = [
            'secure', 'account', 'verify', 'update', 'login', 'signin',
            'banking', 'confirm', 'suspended', 'unusual', 'click', 'here',
            'urgent', 'immediately', 'password', 'credential', 'authentication',
            'validate', 'restore', 'limited', 'ssn', 'social'
        ]
        
        url_lower = url.lower()
        count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
        
        return count
    
    def count_subdomains(self, url: str) -> int:
        """
        Count number of subdomains in URL
        Example: a.b.c.example.com has 3 subdomains
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if ':' in domain:
                domain = domain.split(':')[0]
            
            dots = domain.count('.')
            
            if domain.endswith(('.co.uk', '.com.au', '.co.za', '.co.nz')):
                return max(0, dots - 2)
            
            return max(0, dots - 1)
            
        except:
            return 0
    
    def extract_features(self, url: str) -> Dict[str, Any]:
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
        features['domain_entropy'] = self.calculate_entropy(domain)
        features['suspicious_word_count'] = self.count_suspicious_words(url)
        features['subdomain_count'] = self.count_subdomains(url)
        
        return features
    
    def determine_threat_type(self, is_phishing: bool, confidence: float, url: str) -> Optional[str]:
        """
        Determine threat type based on URL patterns
        
        Args:
            is_phishing: Whether URL is predicted as phishing
            confidence: Prediction confidence score
            url: URL string to analyze
            
        Returns:
            Threat type string or None if not phishing
        """
        if not is_phishing:
            return None
        
        url_lower = url.lower()
        
        # Check for specific threat patterns
        if any(keyword in url_lower for keyword in ['login', 'signin', 'account', 'verify', 'update']):
            return "credential_theft"
        elif any(keyword in url_lower for keyword in ['download', 'install', 'exe', 'apk']):
            return "malware"
        elif any(keyword in url_lower for keyword in ['prize', 'win', 'claim', 'gift']):
            return "scam"
        elif any(keyword in url_lower for keyword in ['bank', 'paypal', 'payment']):
            return "financial_fraud"
        else:
            return "phishing"
    
    def predict(self, url: str) -> Dict[str, Any]:
        """
        Predict if URL is phishing
        
        Args:
            url: URL string to predict
            
        Returns:
            Dictionary with prediction results:
                - is_phishing: bool
                - confidence_score: float
                - threat_type: Optional[str]
                
        Raises:
            RuntimeError: If model is not loaded
        """
        if not self.is_loaded():
            raise RuntimeError("Model is not loaded. Call load_model() first.")
        
        try:
            # Check if domain is in trusted whitelist
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                # Remove www. prefix for comparison
                domain_clean = domain.replace('www.', '')
                
                is_trusted = any(
                    domain_clean == trusted or domain_clean.endswith('.' + trusted)
                    for trusted in self.trusted_domains
                )
            except:
                is_trusted = False
            
            # Extract features
            features = self.extract_features(url)
            
            # Create DataFrame with features in correct order
            X = pd.DataFrame([features])[self.feature_names]
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Make prediction
            prediction = self.model.predict(X_scaled)[0]
            prediction_proba = self.model.predict_proba(X_scaled)[0]
            
            is_phishing = bool(prediction == 1)
            
            # Calculate confidence score as percentage
            # prediction_proba[0] = probability of safe (class 0)
            # prediction_proba[1] = probability of phishing (class 1)
            if is_phishing:
                confidence_score = float(prediction_proba[1] * 100)  # Convert to percentage
            else:
                confidence_score = float(prediction_proba[0] * 100)  # Convert to percentage
            
            # Boost confidence for trusted domains
            if is_trusted and not is_phishing:
                # If trusted domain predicted as safe, boost confidence to minimum 95%
                confidence_score = max(confidence_score, 95.0)
                logger.info(f"Trusted domain detected: {domain_clean}, boosted confidence to {confidence_score:.2f}%")
            elif is_trusted and is_phishing:
                # If trusted domain predicted as phishing, it's likely a false positive
                # Override to safe with high confidence
                is_phishing = False
                confidence_score = 98.0
                logger.info(f"Trusted domain detected but flagged as phishing - overriding to SAFE: {domain_clean}")
            
            # Determine threat type
            threat_type = self.determine_threat_type(is_phishing, confidence_score, url)
            
            logger.info(f"Prediction: is_phishing={is_phishing}, confidence={confidence_score:.2f}, threat={threat_type}")
            
            return {
                "is_phishing": is_phishing,
                "confidence_score": confidence_score,
                "threat_type": threat_type
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            raise
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about loaded model
        
        Returns:
            Dictionary with model information
        """
        if not self.is_loaded():
            return {
                "loaded": False,
                "message": "Model not loaded"
            }
        
        return {
            "loaded": True,
            "model_type": type(self.model).__name__,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names
        }


# Global instance (Singleton)
phishing_predictor = PhishingPredictor()
