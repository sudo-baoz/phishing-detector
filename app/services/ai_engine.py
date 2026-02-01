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
    
    
    def _find_model_file(self, model_name: str = "phishing_model.pkl") -> Optional[Path]:
        """
        Tự động tìm file model ở nhiều vị trí khác nhau
        Hỗ trợ cả local dev, Docker, và VPS deployment
        
        Args:
            model_name: Tên file model (mặc định: phishing_model.pkl)
            
        Returns:
            Path object nếu tìm thấy, None nếu không
        """
        # Danh sách các vị trí có thể chứa model
        search_paths = [
            # 1. Thư mục models/ (local dev)
            Path("models") / model_name,
            Path("models") / "advanced_model.pkl",  # Fallback name
            
            # 2. Root directory (khi deploy)
            Path(model_name),
            Path("advanced_model.pkl"),
            
            # 3. Parent directory
            Path("..") / "models" / model_name,
            Path("..") / model_name,
            
            # 4. Docker container paths
            Path("/app/models") / model_name,
            Path("/app") / model_name,
            
            # 5. Absolute path từ script location
            Path(__file__).parent.parent / "models" / model_name,
            Path(__file__).parent.parent / model_name,
        ]
        
        logger.info(f"🔍 Searching for model file: {model_name}")
        
        for path in search_paths:
            try:
                # Resolve để lấy absolute path và check existence
                resolved_path = path.resolve()
                if resolved_path.exists() and resolved_path.is_file():
                    logger.info(f"✅ Found model at: {resolved_path}")
                    return resolved_path
                else:
                    logger.debug(f"❌ Not found: {resolved_path}")
            except Exception as e:
                logger.debug(f"Error checking path {path}: {e}")
                continue
        
        logger.error(f"❌ Model file '{model_name}' not found in any search path")
        return None
    
    def load_model(self, model_path: Optional[str] = None) -> bool:
        """
        Load trained ML model from file
        Tự động tìm file nếu không cung cấp path cụ thể
        
        Args:
            model_path: Path to the pickled model file (optional)
                       Nếu None, sẽ tự động tìm kiếm
            
        Returns:
            bool: True if successful, False otherwise
            
        Raises:
            FileNotFoundError: If model file doesn't exist
            Exception: For other loading errors
        """
        # Nếu cung cấp path cụ thể, dùng nó
        if model_path:
            path = Path(model_path)
            if not path.exists():
                logger.error(f"Specified model file not found: {path}")
                raise FileNotFoundError(f"Model file not found: {path}")
        else:
            # Tự động tìm kiếm file model
            path = self._find_model_file()
            if path is None:
                raise FileNotFoundError(
                    "Could not find model file. Searched locations:\n"
                    "- models/phishing_model.pkl\n"
                    "- models/advanced_model.pkl\n"
                    "- ./phishing_model.pkl\n"
                    "- /app/models/phishing_model.pkl (Docker)\n"
                    "Please ensure model file exists in one of these locations."
                )
        
        try:
            logger.info(f"📦 Loading ML model from: {path}")
            model_package = joblib.load(path)
            
            self.model = model_package['model']
            self.scaler = model_package['scaler']
            self.feature_names = model_package['feature_names']
            
            # Log additional info from advanced model
            if 'best_params' in model_package:
                logger.info("✅ Advanced ML Model loaded successfully")
                logger.info(f"  - Model type: {type(self.model).__name__} (Optimized with RandomizedSearchCV)")
                logger.info(f"  - Features: {len(self.feature_names)}")
                logger.info(f"  - CV F1 Score: {model_package.get('cv_score', 'N/A')}")
                logger.info(f"  - Test Accuracy: {model_package.get('test_accuracy', 'N/A')}")
            else:
                logger.info("✅ ML Model loaded successfully")
                logger.info(f"  - Model type: {type(self.model).__name__}")
                logger.info(f"  - Features: {len(self.feature_names)}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to load ML model: {e}")
            raise
    
    def _generate_training_data(self) -> pd.DataFrame:
        """
        Generate synthetic training data for auto-training
        Returns 200 samples (100 safe, 100 phishing URLs)
        """
        logger.info("🔧 Generating synthetic training data...")
        
        # Safe URLs (legitimate websites)
        safe_urls = [
            'https://www.google.com/search', 'https://www.facebook.com/profile',
            'https://github.com/trending', 'https://stackoverflow.com/questions',
            'https://www.amazon.com/products', 'https://www.youtube.com/watch',
            'https://www.linkedin.com/in', 'https://www.microsoft.com',
            'https://www.apple.com', 'https://www.netflix.com/browse',
            'https://twitter.com/home', 'https://www.reddit.com/r/python',
            'https://www.wikipedia.org/wiki', 'https://www.bbc.com/news',
            'https://www.cnn.com/world', 'https://www.coursera.org/courses',
        ]
        
        # Phishing URLs (suspicious patterns)
        phishing_urls = [
            'http://secure-login-bank.xyz/verify', 'https://paypal-security-check.com/account',
            'http://amazon-prime-renew.tk/payment', 'https://apple-id-unlock.ml/signin',
            'http://netflix-billing-update.ga/verify', 'https://microsoft-security-alert.cf/update',
            'http://facebook-verify-account.tk/login', 'https://google-account-recovery.ml/reset',
            'http://instagram-support-team.ga/verify', 'https://twitter-verification-badge.tk/apply',
            'http://linkedin-premium-free.ml/signup', 'https://amazon-gift-card-1000.xyz/claim',
            'http://paypal-money-received.tk/accept', 'https://bank-security-department.ga/urgent',
            'http://www-paypal-com-login.tk', 'https://secure-amazon-signin.ml',
        ]
        
        # Generate variations to reach 100 samples each
        import random
        safe_variations = safe_urls.copy()
        while len(safe_variations) < 100:
            url = random.choice(safe_urls)
            variations = [
                f"{url}/page{random.randint(1,100)}",
                f"{url}?id={random.randint(1000,9999)}",
                f"{url}#section{random.randint(1,10)}",
                f"{url}/search?q=test",
            ]
            safe_variations.extend(variations)
        
        phishing_variations = phishing_urls.copy()
        while len(phishing_variations) < 100:
            url = random.choice(phishing_urls)
            variations = [
                f"{url}?token=abc{random.randint(100,999)}",
                f"{url}&session=xyz",
                f"{url}/confirm.php",
                f"{url}?user=admin",
            ]
            phishing_variations.extend(variations)
        
        # Create DataFrame with exactly 100 of each
        data = {
            'url': safe_variations[:100] + phishing_variations[:100],
            'label': [0] * 100 + [1] * 100  # 0 = safe, 1 = phishing
        }
        
        df = pd.DataFrame(data)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
        
        logger.info(f"✅ Generated {len(df)} training samples (Safe: {(df['label']==0).sum()}, Phishing: {(df['label']==1).sum()})")
        return df
    
    def auto_train(self, save_path: str = "models/phishing_model.pkl") -> bool:
        """
        Automatically train a new model using synthetic data
        Called when no pre-trained model is found on VPS deployment
        
        Args:
            save_path: Where to save the trained model
            
        Returns:
            bool: True if training successful
        """
        try:
            from sklearn.model_selection import train_test_split
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
            import numpy as np
            
            logger.info("=" * 70)
            logger.info("🤖 AUTO-TRAINING MODE ACTIVATED")
            logger.info("=" * 70)
            logger.info("No pre-trained model found. Training new model with synthetic data...")
            
            # Generate training data
            df = self._generate_training_data()
            
            # Extract features
            logger.info("📊 Extracting features...")
            features_list = []
            for url in df['url']:
                features_list.append(self.extract_features(url))
            
            X = pd.DataFrame(features_list)
            y = df['label']
            
            logger.info(f"✅ Extracted {len(X.columns)} features")
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            logger.info(f"📈 Training set: {len(X_train)}, Test set: {len(X_test)}")
            
            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Train model
            logger.info("🧠 Training RandomForestClassifier...")
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test_scaled)
            accuracy = np.mean(y_pred == y_test)
            logger.info(f"✅ Training complete! Accuracy: {accuracy * 100:.2f}%")
            
            # Save model
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            model_package = {
                'model': model,
                'scaler': scaler,
                'feature_names': X.columns.tolist(),
                'accuracy': accuracy,
                'auto_trained': True,
                'trained_date': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            joblib.dump(model_package, save_path)
            logger.info(f"💾 Model saved to: {save_path}")
            
            # Load the newly trained model
            self.model = model
            self.scaler = scaler
            self.feature_names = X.columns.tolist()
            
            logger.info("=" * 70)
            logger.info("🎉 AUTO-TRAINING SUCCESSFUL!")
            logger.info("=" * 70)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Auto-training failed: {e}")
            return False
    
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
        """Count occurrences of suspicious keywords (matches train_pro.py)"""
        suspicious_keywords = [
            'login', 'verify', 'update', 'banking', 'secure',
            'account', 'signin', 'confirm', 'suspend', 'password'
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
        Extract 18 comprehensive features from URL for advanced ML model
        Matches train_pro.py feature extraction
        
        Args:
            url: URL string to extract features from
            
        Returns:
            Dictionary of 18 feature names and values
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
        except:
            parsed = None
            domain = ""
            path = ""
            query = ""
        
        # Count letters for digit ratio
        letter_count = sum(c.isalpha() for c in url)
        digit_count = sum(c.isdigit() for c in url)
        
        # 18 features matching train_pro.py
        features = {
            # Lexical features (6)
            'url_length': len(url),
            'dot_count': url.count('.'),
            'at_count': url.count('@'),
            'dash_count': url.count('-'),
            'double_slash_count': url.count('//'),
            'has_https': 1 if url.startswith('https://') else 0,
            
            # Entropy feature (1)
            'domain_entropy': self.calculate_entropy(domain),
            
            # Suspicious keyword feature (1)
            'suspicious_word_count': self.count_suspicious_words(url),
            
            # Digit analysis (3)
            'digit_count': digit_count,
            'letter_count': letter_count,
            'digit_ratio': digit_count / letter_count if letter_count > 0 else 0.0,
            
            # Advanced detection features (7)
            'subdomain_count': self.count_subdomains(url),
            'has_ip': 1 if any(c.isdigit() for c in domain.split('.')) and 
                          all(part.isdigit() and 0 <= int(part) <= 255 
                              for part in domain.split('.') if part.isdigit()) else 0,
            'special_char_count': sum(c in '!@#$%^&*()_+=[]{}|;:,<>?~`' for c in url),
            'path_length': len(path),
            'has_port': 1 if ':' in domain and any(c.isdigit() for c in domain.split(':')[-1]) else 0,
            'query_length': len(query),
            'tld_suspicious': 1 if any(url.endswith(tld) for tld in 
                                       ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.club']) else 0,
        }
        
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
