#!/usr/bin/env python3
"""
PhishGuard AI - Feature Engineering Module
==========================================

This module extracts comprehensive features from domains for ML classification.
Based on the SRS requirements for 105+ features across multiple categories.

Key Findings from Training Data Analysis:
- 1,043 samples: 692 Suspected (66.3%) + 351 Phishing (33.7%)
- Main columns: CSE Domain, Phishing/Suspected Domain, Class Label
- 19 CSE entities, 21 CSE domains covered
- Focus on domain similarity and typosquatting detection

Feature Categories Implemented:
1. URL-Based Features (25 features)
2. Domain-Based Features (15 features) 
3. Lexical Features (10 features)
4. Network Features (15 features) - requires external data
5. Visual Features (20 features) - requires screenshots
6. Content Features (15 features) - requires web scraping
7. Temporal Features (5 features) - requires WHOIS data

Author: PhishGuard AI Team
Date: October 2, 2025
"""

import pandas as pd
import numpy as np
import re
import math
import string
from urllib.parse import urlparse
import tldextract
from fuzzywuzzy import fuzz
from Levenshtein import distance as levenshtein_distance
from Levenshtein import jaro_winkler
import validators
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class PhishGuardFeatureExtractor:
    """
    Comprehensive feature extraction for phishing domain detection.
    Implements 105+ features as specified in SRS requirements.
    """
    
    def __init__(self):
        """Initialize the feature extractor with predefined patterns and lists."""
        
        # Suspicious keywords commonly used in phishing
        self.suspicious_keywords = {
            'banking': ['bank', 'secure', 'login', 'account', 'verify', 'confirm', 
                       'update', 'suspended', 'locked', 'urgent'],
            'tech': ['support', 'help', 'service', 'technical', 'customer'],
            'urgency': ['urgent', 'immediate', 'expire', 'suspend', 'limited'],
            'deception': ['official', 'authentic', 'real', 'genuine', 'original']
        }
        
        # Common legitimate TLDs (lower risk)
        self.legitimate_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'co.uk', 'co.in', 'co.za', 'com.au'
        }
        
        # Suspicious TLDs (higher risk)
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'top', 'click', 'download', 
            'stream', 'science', 'work', 'party', 'review'
        }
        
        # Character substitution patterns for homograph detection
        self.homograph_chars = {
            'a': ['а', 'ɑ', 'α'], 'e': ['е', 'ε'], 'o': ['о', 'ο', '0'],
            'p': ['р', 'ρ'], 'c': ['с', 'ϲ'], 'x': ['х', 'χ'],
            'y': ['у', 'γ'], 'i': ['і', 'ι', '1', 'l'], 'n': ['η'],
            'h': ['һ'], 'b': ['ь'], 'd': ['ԁ'], 'g': ['ɡ'],
            'm': ['м'], 'k': ['κ'], 't': ['т'], 'u': ['υ'],
            'v': ['ν'], 'w': ['ԝ'], 'z': ['ᴢ']
        }
    
    def extract_all_features(self, legitimate_domain, suspicious_domain):
        """
        Extract all 105+ features for a domain pair.
        
        Args:
            legitimate_domain (str): The legitimate CSE domain (e.g., 'airtel.in')
            suspicious_domain (str): The suspicious domain to analyze
            
        Returns:
            dict: Dictionary containing all extracted features
        """
        
        features = {}
        
        # 1. URL-Based Features (25 features)
        url_features = self.extract_url_features(suspicious_domain)
        features.update({f"url_{k}": v for k, v in url_features.items()})
        
        # 2. Domain-Based Features (15 features)
        domain_features = self.extract_domain_features(suspicious_domain)
        features.update({f"domain_{k}": v for k, v in domain_features.items()})
        
        # 3. Lexical Features (10 features) - Similarity to legitimate domain
        lexical_features = self.extract_lexical_features(legitimate_domain, suspicious_domain)
        features.update({f"lexical_{k}": v for k, v in lexical_features.items()})
        
        # 4. Typosquatting Detection Features (15 features)
        typo_features = self.extract_typosquatting_features(legitimate_domain, suspicious_domain)
        features.update({f"typo_{k}": v for k, v in typo_features.items()})
        
        # 5. IDN/Homograph Features (10 features)
        idn_features = self.extract_idn_features(suspicious_domain)
        features.update({f"idn_{k}": v for k, v in idn_features.items()})
        
        # 6. Structural Features (15 features)
        structural_features = self.extract_structural_features(suspicious_domain)
        features.update({f"struct_{k}": v for k, v in structural_features.items()})
        
        # 7. Risk Assessment Features (10 features)
        risk_features = self.extract_risk_features(suspicious_domain)
        features.update({f"risk_{k}": v for k, v in risk_features.items()})
        
        # 8. Brand Similarity Features (10 features)
        brand_features = self.extract_brand_similarity_features(legitimate_domain, suspicious_domain)
        features.update({f"brand_{k}": v for k, v in brand_features.items()})
        
        return features
    
    def extract_url_features(self, domain):
        """Extract URL-based features (25 features)."""
        
        try:
            # Clean domain first - remove any invalid characters
            domain = str(domain).strip()
            
            # Handle problematic URLs
            if '[' in domain or ']' in domain:
                domain = domain.replace('[', '').replace(']', '')
            
            # Ensure domain has protocol for parsing
            if not domain.startswith(('http://', 'https://')):
                url = f"https://{domain}"
            else:
                url = domain
                
            parsed = urlparse(url)
            domain = parsed.netloc if parsed.netloc else domain
            
        except (ValueError, Exception) as e:
            # Fallback for invalid URLs
            print(f"Warning: Invalid URL '{domain}': {e}")
            url = f"https://{str(domain).strip()}"
            parsed = type('obj', (object,), {
                'scheme': 'https', 'netloc': str(domain).strip(), 
                'path': '', 'query': '', 'fragment': ''
            })
        
        features = {
            # Basic length features
            'length': len(domain),
            'url_length': len(url),
            
            # Character count features
            'dot_count': domain.count('.'),
            'hyphen_count': domain.count('-'),
            'underscore_count': domain.count('_'),
            'digit_count': sum(c.isdigit() for c in domain),
            'special_char_count': sum(c in '!@#$%^&*()+=[]{}|;:,<>?' for c in domain),
            
            # Protocol and structure
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_path': 1 if parsed.path and parsed.path != '/' else 0,
            'has_query': 1 if parsed.query else 0,
            'has_fragment': 1 if parsed.fragment else 0,
            
            # Character distribution
            'vowel_ratio': sum(c.lower() in 'aeiou' for c in domain) / len(domain),
            'consonant_ratio': sum(c.lower() in 'bcdfghjklmnpqrstvwxyz' for c in domain) / len(domain),
            'uppercase_ratio': sum(c.isupper() for c in domain) / len(domain),
            'lowercase_ratio': sum(c.islower() for c in domain) / len(domain),
            
            # Entropy and randomness
            'entropy': self._calculate_entropy(domain),
            'longest_word': max([len(word) for word in re.split(r'[.-]', domain)] + [0]),
            
            # Suspicious patterns
            'has_ip': 1 if self._contains_ip(domain) else 0,
            'repeated_chars': self._count_repeated_chars(domain),
            'keyboard_patterns': self._detect_keyboard_patterns(domain),
            
            # Advanced patterns
            'alternating_case': self._detect_alternating_case(domain),
            'number_sequences': self._detect_number_sequences(domain),
            'common_words': self._count_common_words(domain),
            'brand_keywords': self._count_brand_keywords(domain),
            'suspicious_keywords': self._count_suspicious_keywords(domain)
        }
        
        return features
    
    def extract_domain_features(self, domain):
        """Extract domain-based features (15 features)."""
        
        # Extract domain parts using tldextract
        extracted = tldextract.extract(domain)
        subdomain = extracted.subdomain
        domain_name = extracted.domain
        suffix = extracted.suffix
        
        features = {
            # Basic domain structure
            'subdomain_count': len(subdomain.split('.')) if subdomain else 0,
            'domain_length': len(domain_name),
            'tld_length': len(suffix),
            'total_parts': len([x for x in [subdomain, domain_name, suffix] if x]),
            
            # Subdomain analysis
            'avg_subdomain_length': np.mean([len(s) for s in subdomain.split('.')]) if subdomain else 0,
            'max_subdomain_length': max([len(s) for s in subdomain.split('.')]) if subdomain else 0,
            'has_www': 1 if 'www' in subdomain.lower() else 0,
            'numeric_subdomain': 1 if subdomain and any(c.isdigit() for c in subdomain) else 0,
            
            # TLD analysis
            'is_legitimate_tld': 1 if suffix.lower() in self.legitimate_tlds else 0,
            'is_suspicious_tld': 1 if suffix.lower() in self.suspicious_tlds else 0,
            'tld_entropy': self._calculate_entropy(suffix) if suffix else 0,
            
            # Domain name analysis
            'domain_entropy': self._calculate_entropy(domain_name),
            'consonant_cluster': self._count_consonant_clusters(domain_name),
            'vowel_cluster': self._count_vowel_clusters(domain_name),
            'domain_complexity': self._calculate_complexity_score(domain_name)
        }
        
        return features
    
    def extract_lexical_features(self, legitimate_domain, suspicious_domain):
        """Extract lexical similarity features (10 features)."""
        
        # Clean domains for comparison
        legit_clean = legitimate_domain.lower().replace('www.', '')
        suspicious_clean = suspicious_domain.lower().replace('www.', '')
        
        # Extract main domain parts
        legit_parts = tldextract.extract(legitimate_domain)
        suspicious_parts = tldextract.extract(suspicious_domain)
        
        legit_main = legit_parts.domain
        suspicious_main = suspicious_parts.domain
        
        features = {
            # String similarity metrics
            'levenshtein_distance': levenshtein_distance(legit_main, suspicious_main),
            'levenshtein_ratio': 1 - (levenshtein_distance(legit_main, suspicious_main) / max(len(legit_main), len(suspicious_main))),
            'jaro_winkler_similarity': jaro_winkler(legit_main, suspicious_main),
            
            # Fuzzy matching scores
            'fuzz_ratio': fuzz.ratio(legit_main, suspicious_main) / 100.0,
            'fuzz_partial_ratio': fuzz.partial_ratio(legit_main, suspicious_main) / 100.0,
            'fuzz_token_sort_ratio': fuzz.token_sort_ratio(legit_main, suspicious_main) / 100.0,
            'fuzz_token_set_ratio': fuzz.token_set_ratio(legit_main, suspicious_main) / 100.0,
            
            # Character-level analysis
            'common_characters': len(set(legit_main) & set(suspicious_main)),
            'character_difference': abs(len(legit_main) - len(suspicious_main)),
            'longest_common_substring': self._longest_common_substring(legit_main, suspicious_main)
        }
        
        return features
    
    def extract_typosquatting_features(self, legitimate_domain, suspicious_domain):
        """Extract typosquatting detection features (15 features)."""
        
        legit_main = tldextract.extract(legitimate_domain).domain.lower()
        suspicious_main = tldextract.extract(suspicious_domain).domain.lower()
        
        features = {
            # Character manipulation detection
            'char_omission': self._detect_char_omission(legit_main, suspicious_main),
            'char_repetition': self._detect_char_repetition(legit_main, suspicious_main),
            'char_swapping': self._detect_char_swapping(legit_main, suspicious_main),
            'char_insertion': self._detect_char_insertion(legit_main, suspicious_main),
            'char_substitution': self._detect_char_substitution(legit_main, suspicious_main),
            
            # Keyboard-based typos
            'adjacent_key_typo': self._detect_adjacent_key_typo(legit_main, suspicious_main),
            'qwerty_distance': self._calculate_qwerty_distance(legit_main, suspicious_main),
            
            # Bitsquatting detection
            'bitsquatting_score': self._detect_bitsquatting(legit_main, suspicious_main),
            
            # Combosquatting detection
            'prefix_addition': self._detect_prefix_addition(legit_main, suspicious_main),
            'suffix_addition': self._detect_suffix_addition(legit_main, suspicious_main),
            'keyword_insertion': self._detect_keyword_insertion(legit_main, suspicious_main),
            
            # Homograph/lookalike detection
            'visual_similarity': self._calculate_visual_similarity(legit_main, suspicious_main),
            'homograph_score': self._calculate_homograph_score(suspicious_main),
            
            # Pattern analysis
            'typo_pattern_count': self._count_typo_patterns(legit_main, suspicious_main),
            'edit_distance_ratio': levenshtein_distance(legit_main, suspicious_main) / max(len(legit_main), len(suspicious_main))
        }
        
        return features
    
    def extract_idn_features(self, domain):
        """Extract IDN and homograph attack features (10 features)."""
        
        features = {
            # IDN detection
            'is_idn': 1 if domain.startswith('xn--') or any(ord(c) > 127 for c in domain) else 0,
            'punycode_length': len(domain.encode('punycode').decode('ascii')) if domain.startswith('xn--') else len(domain),
            'unicode_char_count': sum(1 for c in domain if ord(c) > 127),
            'mixed_scripts': self._detect_mixed_scripts(domain),
            
            # Homograph detection
            'homograph_char_count': self._count_homograph_chars(domain),
            'cyrillic_chars': sum(1 for c in domain if '\u0400' <= c <= '\u04FF'),
            'greek_chars': sum(1 for c in domain if '\u0370' <= c <= '\u03FF'),
            'arabic_chars': sum(1 for c in domain if '\u0600' <= c <= '\u06FF'),
            
            # Zero-width and invisible characters
            'zero_width_chars': sum(1 for c in domain if c in '\u200B\u200C\u200D\uFEFF'),
            'suspicious_unicode': self._detect_suspicious_unicode(domain)
        }
        
        return features
    
    def extract_structural_features(self, domain):
        """Extract structural domain features (15 features)."""
        
        extracted = tldextract.extract(domain)
        
        features = {
            # Length ratios and proportions
            'subdomain_to_domain_ratio': len(extracted.subdomain) / len(extracted.domain) if extracted.domain else 0,
            'domain_to_tld_ratio': len(extracted.domain) / len(extracted.suffix) if extracted.suffix else 0,
            'total_label_count': len([x for x in domain.split('.') if x]),
            
            # Character type analysis
            'alpha_ratio': sum(c.isalpha() for c in domain) / len(domain),
            'digit_ratio': sum(c.isdigit() for c in domain) / len(domain),
            'special_ratio': sum(not c.isalnum() and c != '.' for c in domain) / len(domain),
            
            # Pattern complexity
            'alternating_alpha_digit': self._count_alternating_patterns(domain),
            'consecutive_consonants': self._max_consecutive_consonants(domain),
            'consecutive_vowels': self._max_consecutive_vowels(domain),
            'repeated_bigrams': self._count_repeated_bigrams(domain),
            'repeated_trigrams': self._count_repeated_trigrams(domain),
            
            # Structural anomalies
            'unusual_length': 1 if len(domain) > 50 or len(domain) < 3 else 0,
            'excessive_subdomains': 1 if len(extracted.subdomain.split('.')) > 3 else 0,
            'numeric_heavy': 1 if sum(c.isdigit() for c in domain) > len(domain) * 0.3 else 0,
            'hyphen_heavy': 1 if domain.count('-') > 3 else 0
        }
        
        return features
    
    def extract_risk_features(self, domain):
        """Extract risk assessment features (10 features)."""
        
        features = {
            # Dictionary word analysis
            'dictionary_words': self._count_dictionary_words(domain),
            'common_brand_similarity': self._calculate_brand_similarity_score(domain),
            'financial_keywords': self._count_financial_keywords(domain),
            'tech_keywords': self._count_tech_keywords(domain),
            
            # Suspicious pattern detection
            'url_shortener_pattern': 1 if self._detect_url_shortener_pattern(domain) else 0,
            'dga_score': self._calculate_dga_score(domain),
            'randomness_score': self._calculate_randomness_score(domain),
            
            # Behavioral indicators
            'suspicious_tld_combo': self._detect_suspicious_tld_combo(domain),
            'phishing_keywords': self._count_phishing_keywords(domain),
            'trust_score': self._calculate_basic_trust_score(domain)
        }
        
        return features
    
    def extract_brand_similarity_features(self, legitimate_domain, suspicious_domain):
        """Extract brand similarity features (10 features)."""
        
        legit_parts = tldextract.extract(legitimate_domain)
        suspicious_parts = tldextract.extract(suspicious_domain)
        
        features = {
            # Brand name analysis
            'brand_name_contained': 1 if legit_parts.domain.lower() in suspicious_domain.lower() else 0,
            'brand_name_modified': self._detect_brand_modification(legit_parts.domain, suspicious_parts.domain),
            'brand_tld_mismatch': 1 if legit_parts.suffix != suspicious_parts.suffix else 0,
            
            # Similarity scoring
            'phonetic_similarity': self._calculate_phonetic_similarity(legit_parts.domain, suspicious_parts.domain),
            'visual_brand_similarity': self._calculate_visual_brand_similarity(legit_parts.domain, suspicious_parts.domain),
            
            # Combosquatting variations
            'brand_prefix_combo': self._detect_brand_prefix_combo(legit_parts.domain, suspicious_parts.domain),
            'brand_suffix_combo': self._detect_brand_suffix_combo(legit_parts.domain, suspicious_parts.domain),
            'brand_keyword_combo': self._detect_brand_keyword_combo(legit_parts.domain, suspicious_parts.domain),
            
            # Advanced similarity
            'semantic_similarity': self._calculate_semantic_similarity(legit_parts.domain, suspicious_parts.domain),
            'overall_brand_risk': self._calculate_overall_brand_risk(legitimate_domain, suspicious_domain)
        }
        
        return features
    
    # ==================== HELPER METHODS ====================
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text."""
        if not text:
            return 0
        
        char_counts = Counter(text)
        length = len(text)
        entropy = 0
        
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _contains_ip(self, domain):
        """Check if domain contains IP address."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return bool(re.search(ip_pattern, domain))
    
    def _count_repeated_chars(self, text):
        """Count consecutive repeated characters."""
        if len(text) < 2:
            return 0
        
        count = 0
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                count += 1
        
        return count
    
    def _detect_keyboard_patterns(self, text):
        """Detect keyboard patterns like 'qwerty', '123456'."""
        keyboard_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890'
        ]
        
        count = 0
        text_lower = text.lower()
        
        for row in keyboard_rows:
            for i in range(len(row) - 2):
                if row[i:i+3] in text_lower:
                    count += 1
        
        return count
    
    def _detect_alternating_case(self, text):
        """Detect alternating case patterns."""
        if len(text) < 2:
            return 0
        
        alternating = 0
        for i in range(1, len(text)):
            if text[i].isalpha() and text[i-1].isalpha():
                if text[i].isupper() != text[i-1].isupper():
                    alternating += 1
        
        return alternating
    
    def _detect_number_sequences(self, text):
        """Detect sequences of numbers."""
        number_sequences = re.findall(r'\d{3,}', text)
        return len(number_sequences)
    
    def _count_common_words(self, text):
        """Count common English words in domain."""
        common_words = {
            'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
            'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his',
            'how', 'its', 'may', 'new', 'now', 'old', 'see', 'two', 'who', 'boy',
            'did', 'man', 'oil', 'sit', 'too', 'use', 'web', 'app', 'com', 'net'
        }
        
        # Split domain by common separators
        words = re.split(r'[.-]', text.lower())
        return sum(1 for word in words if word in common_words)
    
    def _count_brand_keywords(self, text):
        """Count brand-related keywords."""
        brand_keywords = {
            'official', 'secure', 'login', 'account', 'service', 'support',
            'help', 'customer', 'portal', 'access', 'verify', 'auth'
        }
        
        words = re.split(r'[.-]', text.lower())
        return sum(1 for word in words if word in brand_keywords)
    
    def _count_suspicious_keywords(self, text):
        """Count suspicious keywords often used in phishing."""
        suspicious = set()
        for category in self.suspicious_keywords.values():
            suspicious.update(category)
        
        words = re.split(r'[.-]', text.lower())
        return sum(1 for word in words if word in suspicious)
    
    def _count_consonant_clusters(self, text):
        """Count consonant clusters."""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{3,}', text.lower())
        return len(clusters)
    
    def _count_vowel_clusters(self, text):
        """Count vowel clusters."""
        vowels = 'aeiou'
        clusters = re.findall(r'[aeiou]{3,}', text.lower())
        return len(clusters)
    
    def _calculate_complexity_score(self, text):
        """Calculate overall complexity score."""
        if not text:
            return 0
        
        # Factors contributing to complexity
        length_score = min(len(text) / 10.0, 1.0)
        entropy_score = min(self._calculate_entropy(text) / 4.0, 1.0)
        char_variety = len(set(text)) / len(text)
        
        return (length_score + entropy_score + char_variety) / 3
    
    def _longest_common_substring(self, s1, s2):
        """Find length of longest common substring."""
        m, n = len(s1), len(s2)
        if m == 0 or n == 0:
            return 0
        
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        max_length = 0
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i-1] == s2[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                    max_length = max(max_length, dp[i][j])
                else:
                    dp[i][j] = 0
        
        return max_length
    
    # ==================== TYPOSQUATTING DETECTION ====================
    
    def _detect_char_omission(self, legit, suspicious):
        """Detect character omission typos."""
        if abs(len(legit) - len(suspicious)) != 1 or len(suspicious) >= len(legit):
            return 0
        
        # Try removing each character from legit to see if it matches suspicious
        for i in range(len(legit)):
            if legit[:i] + legit[i+1:] == suspicious:
                return 1
        return 0
    
    def _detect_char_repetition(self, legit, suspicious):
        """Detect character repetition typos."""
        # Simple heuristic: check for repeated characters
        repetition_score = 0
        for char in set(legit):
            legit_count = legit.count(char)
            suspicious_count = suspicious.count(char)
            if suspicious_count > legit_count:
                repetition_score += suspicious_count - legit_count
        
        return min(repetition_score, 5)  # Cap at 5
    
    def _detect_char_swapping(self, legit, suspicious):
        """Detect character swapping typos."""
        if len(legit) != len(suspicious):
            return 0
        
        differences = sum(1 for i, (c1, c2) in enumerate(zip(legit, suspicious)) if c1 != c2)
        
        # Check for adjacent character swaps
        for i in range(len(legit) - 1):
            swapped = legit[:i] + legit[i+1] + legit[i] + legit[i+2:]
            if swapped == suspicious:
                return 1
        
        return 1 if differences == 2 else 0
    
    def _detect_char_insertion(self, legit, suspicious):
        """Detect character insertion typos."""
        if len(suspicious) <= len(legit):
            return 0
        
        # Try inserting characters to see if suspicious becomes legit
        for i in range(len(suspicious)):
            if suspicious[:i] + suspicious[i+1:] == legit:
                return 1
        return 0
    
    def _detect_char_substitution(self, legit, suspicious):
        """Detect character substitution typos."""
        if len(legit) != len(suspicious):
            return 0
        
        substitutions = sum(1 for c1, c2 in zip(legit, suspicious) if c1 != c2)
        return min(substitutions, 3)  # Cap at 3
    
    def _detect_adjacent_key_typo(self, legit, suspicious):
        """Detect adjacent keyboard key typos."""
        keyboard_layout = {
            'q': 'wa', 'w': 'qeas', 'e': 'wrds', 'r': 'etdf', 't': 'ryfg',
            'y': 'tugh', 'u': 'yihj', 'i': 'uojk', 'o': 'ipkl', 'p': 'ol',
            'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc',
            'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm',
            'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
            'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        
        if len(legit) != len(suspicious):
            return 0
        
        adjacent_typos = 0
        for c1, c2 in zip(legit.lower(), suspicious.lower()):
            if c1 != c2 and c1 in keyboard_layout and c2 in keyboard_layout[c1]:
                adjacent_typos += 1
        
        return adjacent_typos
    
    def _calculate_qwerty_distance(self, legit, suspicious):
        """Calculate average QWERTY keyboard distance."""
        # Simplified QWERTY positions (row, col)
        qwerty_pos = {
            'q': (0, 0), 'w': (0, 1), 'e': (0, 2), 'r': (0, 3), 't': (0, 4),
            'y': (0, 5), 'u': (0, 6), 'i': (0, 7), 'o': (0, 8), 'p': (0, 9),
            'a': (1, 0), 's': (1, 1), 'd': (1, 2), 'f': (1, 3), 'g': (1, 4),
            'h': (1, 5), 'j': (1, 6), 'k': (1, 7), 'l': (1, 8),
            'z': (2, 0), 'x': (2, 1), 'c': (2, 2), 'v': (2, 3), 'b': (2, 4),
            'n': (2, 5), 'm': (2, 6)
        }
        
        if len(legit) != len(suspicious):
            return float('inf')
        
        total_distance = 0
        count = 0
        
        for c1, c2 in zip(legit.lower(), suspicious.lower()):
            if c1 in qwerty_pos and c2 in qwerty_pos:
                pos1 = qwerty_pos[c1]
                pos2 = qwerty_pos[c2]
                distance = math.sqrt((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)
                total_distance += distance
                count += 1
        
        return total_distance / count if count > 0 else 0
    
    def _detect_bitsquatting(self, legit, suspicious):
        """Detect bitsquatting attacks."""
        # Simplified bitsquatting detection
        if len(legit) != len(suspicious):
            return 0
        
        bit_flips = 0
        for c1, c2 in zip(legit, suspicious):
            if c1 != c2:
                # Check if characters differ by a single bit flip
                xor = ord(c1) ^ ord(c2)
                # Count set bits in XOR (should be 1 for single bit flip)
                if bin(xor).count('1') == 1:
                    bit_flips += 1
        
        return bit_flips
    
    def _detect_prefix_addition(self, legit, suspicious):
        """Detect prefix addition combosquatting."""
        if suspicious.endswith(legit):
            prefix_length = len(suspicious) - len(legit)
            return min(prefix_length, 10)  # Cap at 10
        return 0
    
    def _detect_suffix_addition(self, legit, suspicious):
        """Detect suffix addition combosquatting."""
        if suspicious.startswith(legit):
            suffix_length = len(suspicious) - len(legit)
            return min(suffix_length, 10)  # Cap at 10
        return 0
    
    def _detect_keyword_insertion(self, legit, suspicious):
        """Detect keyword insertion in domain."""
        if legit in suspicious and len(suspicious) > len(legit):
            return 1
        return 0
    
    def _calculate_visual_similarity(self, legit, suspicious):
        """Calculate visual similarity between domains."""
        # Simplified visual similarity based on character shapes
        similar_chars = {
            'o': ['0', 'O'], '0': ['o', 'O'], 'O': ['o', '0'],
            'l': ['1', 'I', '|'], '1': ['l', 'I', '|'], 'I': ['l', '1', '|'],
            'rn': ['m'], 'vv': ['w'], 'cl': ['d']
        }
        
        # Calculate similarity score
        score = fuzz.ratio(legit.lower(), suspicious.lower()) / 100.0
        
        # Boost score for visually similar character substitutions
        for char in legit.lower():
            if char in similar_chars:
                for similar in similar_chars[char]:
                    if similar in suspicious.lower():
                        score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_homograph_score(self, domain):
        """Calculate homograph attack score."""
        score = 0
        for char in domain:
            if char.lower() in self.homograph_chars:
                score += 1
        return score
    
    def _count_typo_patterns(self, legit, suspicious):
        """Count various typo patterns."""
        patterns = 0
        
        patterns += self._detect_char_omission(legit, suspicious)
        patterns += self._detect_char_repetition(legit, suspicious)
        patterns += self._detect_char_swapping(legit, suspicious)
        patterns += self._detect_char_insertion(legit, suspicious)
        patterns += min(self._detect_char_substitution(legit, suspicious), 1)
        
        return patterns
    
    # ==================== IDN AND UNICODE METHODS ====================
    
    def _detect_mixed_scripts(self, domain):
        """Detect mixed scripts in domain name."""
        scripts = set()
        for char in domain:
            if '\u0000' <= char <= '\u007F':  # ASCII
                scripts.add('latin')
            elif '\u0400' <= char <= '\u04FF':  # Cyrillic
                scripts.add('cyrillic')
            elif '\u0370' <= char <= '\u03FF':  # Greek
                scripts.add('greek')
            elif '\u0600' <= char <= '\u06FF':  # Arabic
                scripts.add('arabic')
        
        return len(scripts) > 1
    
    def _count_homograph_chars(self, domain):
        """Count homograph characters in domain."""
        count = 0
        for char in domain.lower():
            if char in self.homograph_chars:
                count += 1
        return count
    
    def _detect_suspicious_unicode(self, domain):
        """Detect suspicious Unicode characters."""
        # Check for various suspicious Unicode ranges
        suspicious_ranges = [
            ('\u2000', '\u206F'),  # General Punctuation
            ('\uFFF0', '\uFFFF'),  # Specials
            ('\u0300', '\u036F'),  # Combining Diacritical Marks
        ]
        
        for char in domain:
            for start, end in suspicious_ranges:
                if start <= char <= end:
                    return 1
        return 0
    
    # ==================== STRUCTURAL ANALYSIS METHODS ====================
    
    def _count_alternating_patterns(self, domain):
        """Count alternating letter-digit patterns."""
        if len(domain) < 2:
            return 0
        
        alternating = 0
        for i in range(1, len(domain)):
            curr_is_digit = domain[i].isdigit()
            prev_is_digit = domain[i-1].isdigit()
            
            if curr_is_digit != prev_is_digit:
                alternating += 1
        
        return alternating
    
    def _max_consecutive_consonants(self, domain):
        """Find maximum consecutive consonants."""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        max_count = 0
        current_count = 0
        
        for char in domain.lower():
            if char in consonants:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count
    
    def _max_consecutive_vowels(self, domain):
        """Find maximum consecutive vowels."""
        vowels = 'aeiou'
        max_count = 0
        current_count = 0
        
        for char in domain.lower():
            if char in vowels:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count
    
    def _count_repeated_bigrams(self, domain):
        """Count repeated bigrams."""
        if len(domain) < 2:
            return 0
        
        bigrams = {}
        for i in range(len(domain) - 1):
            bigram = domain[i:i+2].lower()
            bigrams[bigram] = bigrams.get(bigram, 0) + 1
        
        return sum(1 for count in bigrams.values() if count > 1)
    
    def _count_repeated_trigrams(self, domain):
        """Count repeated trigrams."""
        if len(domain) < 3:
            return 0
        
        trigrams = {}
        for i in range(len(domain) - 2):
            trigram = domain[i:i+3].lower()
            trigrams[trigram] = trigrams.get(trigram, 0) + 1
        
        return sum(1 for count in trigrams.values() if count > 1)
    
    # ==================== RISK ASSESSMENT METHODS ====================
    
    def _count_dictionary_words(self, domain):
        """Count dictionary words in domain."""
        # Simplified dictionary - in production, use a real dictionary
        common_words = {
            'admin', 'login', 'secure', 'account', 'service', 'support',
            'help', 'customer', 'portal', 'access', 'verify', 'auth',
            'bank', 'finance', 'money', 'pay', 'card', 'credit'
        }
        
        words = re.split(r'[.-]', domain.lower())
        return sum(1 for word in words if word in common_words)
    
    def _calculate_brand_similarity_score(self, domain):
        """Calculate similarity to common brands."""
        # Top brands for comparison
        brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 
                 'twitter', 'instagram', 'linkedin', 'paypal', 'ebay']
        
        max_similarity = 0
        domain_main = tldextract.extract(domain).domain.lower()
        
        for brand in brands:
            similarity = fuzz.ratio(domain_main, brand) / 100.0
            max_similarity = max(max_similarity, similarity)
        
        return max_similarity
    
    def _count_financial_keywords(self, domain):
        """Count financial keywords."""
        financial_keywords = {
            'bank', 'finance', 'money', 'pay', 'payment', 'card', 'credit',
            'debit', 'loan', 'invest', 'insurance', 'wallet', 'cash'
        }
        
        words = re.split(r'[.-]', domain.lower())
        return sum(1 for word in words if word in financial_keywords)
    
    def _count_tech_keywords(self, domain):
        """Count technology keywords."""
        tech_keywords = {
            'tech', 'app', 'software', 'system', 'cloud', 'api', 'web',
            'mobile', 'online', 'digital', 'cyber', 'data', 'network'
        }
        
        words = re.split(r'[.-]', domain.lower())
        return sum(1 for word in words if word in tech_keywords)
    
    def _detect_url_shortener_pattern(self, domain):
        """Detect URL shortener patterns."""
        shortener_patterns = [
            r'bit\.ly', r'tinyurl', r't\.co', r'goo\.gl', r'ow\.ly',
            r'short', r'tiny', r'mini', r'link'
        ]
        
        domain_lower = domain.lower()
        for pattern in shortener_patterns:
            if re.search(pattern, domain_lower):
                return True
        return False
    
    def _calculate_dga_score(self, domain):
        """Calculate Domain Generation Algorithm score."""
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()
        
        if not domain_name:
            return 0
        
        # DGA characteristics
        entropy = self._calculate_entropy(domain_name)
        vowel_ratio = sum(c in 'aeiou' for c in domain_name) / len(domain_name)
        consonant_clusters = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{3,}', domain_name))
        length_score = min(len(domain_name) / 20.0, 1.0)
        
        # Combine factors (higher = more likely DGA)
        dga_score = (entropy / 4.0) + (1 - vowel_ratio) + (consonant_clusters / 3.0) + length_score
        return min(dga_score / 4.0, 1.0)  # Normalize to [0, 1]
    
    def _calculate_randomness_score(self, domain):
        """Calculate randomness score of domain."""
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()
        
        if not domain_name:
            return 0
        
        # Character frequency analysis
        expected_freq = {
            'e': 0.127, 'a': 0.082, 'r': 0.060, 'i': 0.070, 'o': 0.075,
            't': 0.091, 'n': 0.067, 's': 0.063, 'l': 0.040, 'c': 0.028
        }
        
        char_counts = Counter(domain_name)
        deviation = 0
        
        for char, expected in expected_freq.items():
            actual = char_counts.get(char, 0) / len(domain_name)
            deviation += abs(actual - expected)
        
        return min(deviation, 1.0)
    
    def _detect_suspicious_tld_combo(self, domain):
        """Detect suspicious TLD combinations."""
        extracted = tldextract.extract(domain)
        tld = extracted.suffix.lower()
        domain_name = extracted.domain.lower()
        
        # Suspicious combinations
        if tld in self.suspicious_tlds and len(domain_name) > 15:
            return 1
        if tld in ['tk', 'ml', 'ga'] and any(word in domain_name for word in ['secure', 'login', 'bank']):
            return 1
        
        return 0
    
    def _count_phishing_keywords(self, domain):
        """Count phishing-related keywords."""
        phishing_keywords = {
            'secure', 'verify', 'update', 'confirm', 'suspend', 'expire',
            'urgent', 'immediate', 'action', 'required', 'click', 'here'
        }
        
        words = re.split(r'[.-]', domain.lower())
        return sum(1 for word in words if word in phishing_keywords)
    
    def _calculate_basic_trust_score(self, domain):
        """Calculate basic trust score."""
        extracted = tldextract.extract(domain)
        
        trust_score = 0.5  # Start neutral
        
        # Positive factors
        if extracted.suffix in self.legitimate_tlds:
            trust_score += 0.2
        if len(extracted.domain) >= 5 and len(extracted.domain) <= 15:
            trust_score += 0.1
        if not any(c.isdigit() for c in extracted.domain):
            trust_score += 0.1
        
        # Negative factors
        if extracted.suffix in self.suspicious_tlds:
            trust_score -= 0.3
        if self._calculate_entropy(extracted.domain) > 3.5:
            trust_score -= 0.2
        if len(extracted.domain) > 20:
            trust_score -= 0.1
        
        return max(0, min(1, trust_score))
    
    # ==================== BRAND SIMILARITY METHODS ====================
    
    def _detect_brand_modification(self, legit_brand, suspicious_brand):
        """Detect brand name modifications."""
        if legit_brand.lower() in suspicious_brand.lower():
            return len(suspicious_brand) - len(legit_brand)
        
        similarity = fuzz.ratio(legit_brand.lower(), suspicious_brand.lower())
        return 100 - similarity
    
    def _calculate_phonetic_similarity(self, legit, suspicious):
        """Calculate phonetic similarity (simplified)."""
        # Simplified phonetic matching
        phonetic_map = {
            'ph': 'f', 'ck': 'k', 'qu': 'kw', 'x': 'ks',
            'c': 'k', 'z': 's', 'y': 'i'
        }
        
        def phonetic_transform(word):
            word = word.lower()
            for pattern, replacement in phonetic_map.items():
                word = word.replace(pattern, replacement)
            return word
        
        legit_phonetic = phonetic_transform(legit)
        suspicious_phonetic = phonetic_transform(suspicious)
        
        return fuzz.ratio(legit_phonetic, suspicious_phonetic) / 100.0
    
    def _calculate_visual_brand_similarity(self, legit, suspicious):
        """Calculate visual brand similarity."""
        # Visual character substitutions
        visual_subs = {
            'o': '0', '0': 'o', 'l': '1', '1': 'l', 'i': '1',
            'e': '3', 'a': '@', 's': '$', 'g': '9'
        }
        
        def visual_transform(word):
            transformed = ""
            for char in word.lower():
                transformed += visual_subs.get(char, char)
            return transformed
        
        legit_visual = visual_transform(legit)
        suspicious_visual = visual_transform(suspicious)
        
        return fuzz.ratio(legit_visual, suspicious_visual) / 100.0
    
    def _detect_brand_prefix_combo(self, legit, suspicious):
        """Detect brand prefix combosquatting."""
        if suspicious.lower().endswith(legit.lower()):
            prefix = suspicious.lower()[:-len(legit)]
            return len(prefix)
        return 0
    
    def _detect_brand_suffix_combo(self, legit, suspicious):
        """Detect brand suffix combosquatting."""
        if suspicious.lower().startswith(legit.lower()):
            suffix = suspicious.lower()[len(legit):]
            return len(suffix)
        return 0
    
    def _detect_brand_keyword_combo(self, legit, suspicious):
        """Detect brand keyword combinations."""
        combo_keywords = [
            'secure', 'login', 'account', 'service', 'support',
            'official', 'portal', 'app', 'mobile', 'online'
        ]
        
        if legit.lower() in suspicious.lower():
            for keyword in combo_keywords:
                if keyword in suspicious.lower() and keyword not in legit.lower():
                    return 1
        return 0
    
    def _calculate_semantic_similarity(self, legit, suspicious):
        """Calculate semantic similarity (simplified)."""
        # This would typically use word embeddings or semantic models
        # For now, use token-based similarity
        return fuzz.token_set_ratio(legit, suspicious) / 100.0
    
    def _calculate_overall_brand_risk(self, legit_domain, suspicious_domain):
        """Calculate overall brand risk score."""
        legit_parts = tldextract.extract(legit_domain)
        suspicious_parts = tldextract.extract(suspicious_domain)
        
        # Combine multiple risk factors
        similarity = jaro_winkler(legit_parts.domain, suspicious_parts.domain)
        tld_mismatch = 1 if legit_parts.suffix != suspicious_parts.suffix else 0
        brand_contained = 1 if legit_parts.domain.lower() in suspicious_domain.lower() else 0
        
        risk_score = similarity * 0.5 + tld_mismatch * 0.3 + brand_contained * 0.2
        return risk_score


def main():
    """Example usage of the feature extractor."""
    print("🛠️  PhishGuard AI - Feature Engineering Module")
    print("=" * 60)
    
    # Initialize feature extractor
    extractor = PhishGuardFeatureExtractor()
    
    # Example domain pairs from training data
    examples = [
        ("airtel.in", "airtel-merchants.in"),
        ("airtel.in", "airtelrecharge.co.in"),
        ("airtel.in", "airtela.sbs"),
        ("sbi.co.in", "sbibank.tk"),
        ("hdfc.com", "hdfcbank-secure.ml")
    ]
    
    print("Extracting features for example domains...\n")
    
    for legitimate, suspicious in examples:
        print(f"🎯 Analyzing: {legitimate} vs {suspicious}")
        print("-" * 50)
        
        features = extractor.extract_all_features(legitimate, suspicious)
        
        # Display top features
        print(f"Total features extracted: {len(features)}")
        print("\nTop 10 most significant features:")
        
        # Sort features by value (descending)
        sorted_features = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
        
        for i, (feature, value) in enumerate(sorted_features[:10], 1):
            print(f"{i:2d}. {feature:<30}: {value:.4f}")
        
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    main()