#!/usr/bin/env python3
"""
Basic URL Pattern Analyzer
A simple tool to detect suspicious URL patterns that might indicate phishing attempts.
"""

import re
import urllib.parse
from typing import Dict, List, Tuple

class BasicPhishingDetector:
    def __init__(self):
        # Common legitimate domains for comparison
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'reddit.com', 'twitter.com', 'linkedin.com'
        }
        
        # Suspicious keywords often found in phishing URLs
        self.suspicious_keywords = [
            'secure', 'verify', 'account', 'update', 'confirm', 'login',
            'banking', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'facebook', 'twitter', 'instagram', 'whatsapp', 'telegram'
        ]
        
        # Suspicious TLDs (Top Level Domains)
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc']

    def extract_url_features(self, url: str) -> Dict[str, any]:
        """Extract various features from a URL for analysis."""
        try:
            parsed = urllib.parse.urlparse(url.lower())
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            features = {
                'url': url,
                'domain': domain,
                'path': path,
                'query': query,
                'scheme': parsed.scheme,
                'url_length': len(url),
                'domain_length': len(domain),
                'subdomain_count': len(domain.split('.')) - 2 if domain.count('.') > 1 else 0,
                'has_ip': self._is_ip_address(domain),
                'has_suspicious_tld': any(domain.endswith(tld) for tld in self.suspicious_tlds),
                'suspicious_keyword_count': sum(1 for keyword in self.suspicious_keywords if keyword in url.lower()),
                'dash_count': url.count('-'),
                'dot_count': url.count('.'),
                'slash_count': url.count('/'),
                'question_mark_count': url.count('?'),
                'equals_count': url.count('='),
                'ampersand_count': url.count('&'),
                'has_https': parsed.scheme == 'https',
                'suspicious_port': parsed.port is not None and parsed.port not in [80, 443, 8080]
            }
            
            return features
            
        except Exception as e:
            print(f"Error parsing URL {url}: {e}")
            return {}

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address instead of a proper domain name."""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))

    def calculate_suspicion_score(self, features: Dict[str, any]) -> Tuple[float, List[str]]:
        """Calculate a suspicion score based on URL features."""
        score = 0
        reasons = []
        
        # Length-based scoring
        if features.get('url_length', 0) > 100:
            score += 20
            reasons.append("Unusually long URL")
        
        if features.get('domain_length', 0) > 50:
            score += 15
            reasons.append("Unusually long domain")
        
        # IP address instead of domain
        if features.get('has_ip', False):
            score += 30
            reasons.append("Uses IP address instead of domain name")
        
        # Suspicious TLD
        if features.get('has_suspicious_tld', False):
            score += 25
            reasons.append("Uses suspicious top-level domain")
        
        # Multiple subdomains
        if features.get('subdomain_count', 0) > 3:
            score += 20
            reasons.append("Too many subdomains")
        
        # Suspicious keywords
        keyword_count = features.get('suspicious_keyword_count', 0)
        if keyword_count > 0:
            score += keyword_count * 10
            reasons.append(f"Contains {keyword_count} suspicious keyword(s)")
        
        # Special characters
        if features.get('dash_count', 0) > 5:
            score += 15
            reasons.append("Excessive use of dashes")
        
        # No HTTPS
        if not features.get('has_https', True):
            score += 10
            reasons.append("Not using HTTPS")
        
        # Suspicious port
        if features.get('suspicious_port', False):
            score += 15
            reasons.append("Using non-standard port")
        
        return min(score, 100), reasons

    def analyze_url(self, url: str) -> Dict[str, any]:
        """Analyze a single URL and return detailed results."""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        features = self.extract_url_features(url)
        if not features:
            return {'error': 'Could not parse URL'}
        
        score, reasons = self.calculate_suspicion_score(features)
        
        # Determine risk level
        if score >= 70:
            risk_level = "HIGH RISK"
            classification = "LIKELY PHISHING"
        elif score >= 40:
            risk_level = "MEDIUM RISK"
            classification = "SUSPICIOUS"
        elif score >= 20:
            risk_level = "LOW RISK"
            classification = "POTENTIALLY SUSPICIOUS"
        else:
            risk_level = "LOW RISK"
            classification = "LIKELY LEGITIMATE"
        
        return {
            'url': url,
            'suspicion_score': score,
            'risk_level': risk_level,
            'classification': classification,
            'reasons': reasons,
            'features': features
        }

    def batch_analyze(self, urls: List[str]) -> List[Dict[str, any]]:
        """Analyze multiple URLs at once."""
        results = []
        for url in urls:
            result = self.analyze_url(url)
            results.append(result)
        return results


def main():
    """Demonstration of the basic phishing detector."""
    detector = BasicPhishingDetector()
    
    # Test URLs (mix of legitimate and suspicious)
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login",
        "https://secure-paypal-verification.tk/update-account",
        "https://amazon.com",
        "http://microsoft-security-update-verify-account-now.ml/login?redirect=secure",
        "https://github.com/user/repo",
        "https://my-bank-secure-login-portal-verification.cc/authenticate",
        "https://facebook.com/login"
    ]
    
    print("🛡️  PHISHING WEBSITE DETECTOR - STAGE 1")
    print("=" * 60)
    print()
    
    for url in test_urls:
        result = detector.analyze_url(url)
        
        print(f"🔍 URL: {result['url']}")
        print(f"📊 Suspicion Score: {result['suspicion_score']}/100")
        print(f"⚠️  Risk Level: {result['risk_level']}")
        print(f"🎯 Classification: {result['classification']}")
        
        if result['reasons']:
            print("📋 Suspicious Indicators:")
            for reason in result['reasons']:
                print(f"   • {reason}")
        
        print("-" * 60)
        print()


if __name__ == "__main__":
    main()
