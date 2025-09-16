import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Any, Tuple
import logging
import pickle
import os
import urllib.parse
import re

logger = logging.getLogger(__name__)


class MLClassifier:
    """
    Machine Learning classifier for URL phishing detection
    Uses a combination of URL features and content features
    """

    def __init__(self):
        self.url_model = None
        self.scaler = None
        self.text_vectorizer = None
        self.is_trained = False
        self._initialize_pretrained_model()

    def _initialize_pretrained_model(self):
        """Initialize with a basic pre-trained model for demo purposes"""
        try:
            # For MVP, we'll use a simple rule-based classifier
            # In production, this would load a trained model
            self.url_model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            self.scaler = StandardScaler()
            self.text_vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2)
            )

            # Create dummy training data to fit the transformers
            dummy_features = np.random.rand(100, 15)  # 15 URL features
            dummy_labels = np.random.randint(0, 2, 100)
            dummy_text = ['example text'] * 100

            self.scaler.fit(dummy_features)
            self.text_vectorizer.fit(dummy_text)
            self.url_model.fit(dummy_features, dummy_labels)

            self.is_trained = True
            logger.info("ML classifier initialized with basic model")

        except Exception as e:
            logger.error(f"Failed to initialize ML classifier: {e}")
            self.is_trained = False

    def extract_url_features(self, url: str, analysis_data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from URL and analysis data"""

        features = []

        try:
            parsed = urllib.parse.urlparse(url)

            # Basic URL features
            features.append(len(url))  # URL length
            features.append(len(parsed.netloc))  # Domain length
            features.append(len(parsed.path))  # Path length
            features.append(len(parsed.query))  # Query length
            features.append(url.count('.'))  # Number of dots
            features.append(url.count('-'))  # Number of hyphens
            features.append(url.count('_'))  # Number of underscores
            features.append(url.count('/'))  # Number of slashes
            features.append(int(parsed.netloc.replace('.', '').isdigit()))  # Is IP address

            # Advanced URL features
            features.append(int(len(parsed.netloc.split('.')) > 4))  # Too many subdomains
            features.append(int('bit.ly' in url or 'tinyurl' in url or 'short' in url))  # URL shortener
            features.append(int(bool(re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', url))))  # Contains IP

            # Get analysis data features
            steps = analysis_data.get("steps", {})

            # DNS/WHOIS features
            dns_data = steps.get("dns_whois", {})
            features.append(dns_data.get("domain_age_days", 365) if dns_data.get("domain_age_days") else 365)  # Domain age

            # Redirect features
            http_data = steps.get("http_analysis", {})
            redirect_count = len(http_data.get("redirect_chain", []))
            features.append(redirect_count)  # Number of redirects

            # Content features
            content_data = steps.get("content_analysis", {})
            features.append(int(content_data.get("has_login_form", False)))  # Has login form

        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            # Return default features if extraction fails
            features = [0] * 15

        return np.array(features).reshape(1, -1)

    def extract_text_features(self, analysis_data: Dict[str, Any]) -> str:
        """Extract text content for analysis"""
        text_content = ""

        try:
            steps = analysis_data.get("steps", {})

            # Get page title and meta
            screenshot_data = steps.get("screenshot_analysis", {})
            if screenshot_data.get("page_title"):
                text_content += screenshot_data["page_title"] + " "
            if screenshot_data.get("meta_description"):
                text_content += screenshot_data["meta_description"] + " "
            if screenshot_data.get("viewport_content"):
                text_content += screenshot_data["viewport_content"][:500] + " "  # Limit text

            # Get content from static analysis
            content_data = steps.get("content_analysis", {})
            if content_data.get("title"):
                text_content += content_data["title"] + " "
            if content_data.get("meta_description"):
                text_content += content_data["meta_description"] + " "

        except Exception as e:
            logger.error(f"Text feature extraction failed: {e}")

        return text_content.strip() or "no content"

    def classify(self, url: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify URL as phishing or legitimate

        Returns:
            Dict with classification results
        """
        if not self.is_trained:
            return self._fallback_classification(url, analysis_data)

        try:
            # Extract features
            url_features = self.extract_url_features(url, analysis_data)
            text_content = self.extract_text_features(analysis_data)

            # Scale URL features
            url_features_scaled = self.scaler.transform(url_features)

            # Get prediction from URL features
            url_score = self.url_model.predict_proba(url_features_scaled)[0][1]  # Probability of phishing

            # Text analysis (simple keyword-based for MVP)
            text_score = self._analyze_text_content(text_content)

            # Combine scores
            combined_score = (url_score * 0.7) + (text_score * 0.3)

            # Determine classification
            if combined_score >= 0.7:
                classification = "phishing"
                confidence = min(95, combined_score * 100)
            elif combined_score >= 0.4:
                classification = "suspicious"
                confidence = min(85, combined_score * 100)
            else:
                classification = "legitimate"
                confidence = min(90, (1 - combined_score) * 100)

            return {
                "classification": classification,
                "phishing_score": combined_score,
                "confidence": confidence,
                "url_score": url_score,
                "text_score": text_score,
                "features_used": url_features.flatten().tolist()
            }

        except Exception as e:
            logger.error(f"ML classification failed: {e}")
            return self._fallback_classification(url, analysis_data)

    def _analyze_text_content(self, text: str) -> float:
        """Simple keyword-based text analysis for phishing indicators"""
        if not text:
            return 0.0

        text_lower = text.lower()

        # Phishing keywords and their weights
        phishing_keywords = {
            'verify': 0.3,
            'suspended': 0.4,
            'urgent': 0.3,
            'account': 0.2,
            'login': 0.25,
            'update': 0.2,
            'confirm': 0.25,
            'secure': 0.2,
            'immediately': 0.3,
            'expire': 0.3,
            'click here': 0.4,
            'limited time': 0.3,
            'act now': 0.35,
            'paypal': 0.3,
            'amazon': 0.3,
            'apple': 0.3,
            'microsoft': 0.3,
            'google': 0.3,
            'bank': 0.4,
            'credit card': 0.4,
            'ssn': 0.5,
            'social security': 0.5
        }

        score = 0.0
        for keyword, weight in phishing_keywords.items():
            if keyword in text_lower:
                score += weight

        # Normalize score
        return min(1.0, score / 2.0)

    def _fallback_classification(self, url: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule-based classification when ML is not available"""

        risk_score = 0.0

        # Simple rule-based scoring
        if len(url) > 100:
            risk_score += 0.2

        if 'bit.ly' in url or 'tinyurl' in url:
            risk_score += 0.3

        # Check for IP addresses
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', url):
            risk_score += 0.4

        # Check analysis data
        steps = analysis_data.get("steps", {})
        redirect_count = len(steps.get("http_analysis", {}).get("redirect_chain", []))
        if redirect_count > 2:
            risk_score += 0.3

        content_data = steps.get("content_analysis", {})
        if content_data.get("has_login_form"):
            risk_score += 0.2

        # Determine classification
        if risk_score >= 0.6:
            classification = "phishing"
            confidence = 75
        elif risk_score >= 0.3:
            classification = "suspicious"
            confidence = 70
        else:
            classification = "legitimate"
            confidence = 80

        return {
            "classification": classification,
            "phishing_score": risk_score,
            "confidence": confidence,
            "url_score": risk_score,
            "text_score": 0.0,
            "features_used": []
        }

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the trained model"""
        if not self.is_trained or not hasattr(self.url_model, 'feature_importances_'):
            return {}

        feature_names = [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'dot_count', 'hyphen_count', 'underscore_count', 'slash_count',
            'is_ip', 'many_subdomains', 'url_shortener', 'contains_ip',
            'domain_age', 'redirect_count', 'has_login_form'
        ]

        importances = self.url_model.feature_importances_
        return dict(zip(feature_names, importances))