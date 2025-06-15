"""
CLI Password Strength Analyzer
A comprehensive tool for analyzing password strength with multiple security checks.
"""

import argparse
import re
import math
import hashlib
import requests
import json
import os
from datetime import datetime
from collections import Counter
import getpass

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty', 'letmein',
            'welcome', 'monkey', '1234567890', 'abc123', 'password1', 'welcome1',
            'hello', 'login', 'test', 'guest', 'master', 'root', 'administrator'
        }
        
        self.common_patterns = [
            r'123+', r'abc+', r'qwer+', r'asdf+', r'zxcv+',
            r'(.)\1{2,}',  # Repeated characters
            r'(012|123|234|345|456|567|678|789)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)'  # Sequential letters
        ]
        
        self.results_file = 'password_analysis_log.json'

    def analyze_password(self, password):
        """Main analysis function that returns comprehensive password analysis"""
        analysis = {
            'password_length': len(password),
            'timestamp': datetime.now().isoformat(),
            'checks': {},
            'score': 0,
            'strength': 'Weak',
            'feedback': [],
            'entropy': 0
        }
        
        # Length check
        length_score, length_feedback = self._check_length(password)
        analysis['checks']['length'] = {'score': length_score, 'feedback': length_feedback}
        analysis['score'] += length_score
        
        # Character variety checks
        char_score, char_feedback = self._check_character_variety(password)
        analysis['checks']['character_variety'] = {'score': char_score, 'feedback': char_feedback}
        analysis['score'] += char_score
        
        # Common password check
        common_score, common_feedback = self._check_common_passwords(password)
        analysis['checks']['common_passwords'] = {'score': common_score, 'feedback': common_feedback}
        analysis['score'] += common_score
        
        # Pattern check
        pattern_score, pattern_feedback = self._check_patterns(password)
        analysis['checks']['patterns'] = {'score': pattern_score, 'feedback': pattern_feedback}
        analysis['score'] += pattern_score
        
        # Entropy calculation
        analysis['entropy'] = self._calculate_entropy(password)
        
        # Overall strength determination
        analysis['strength'] = self._determine_strength(analysis['score'])
        
        # Compile feedback
        for check in analysis['checks'].values():
            analysis['feedback'].extend(check['feedback'])
        
        return analysis

    def _check_length(self, password):
        """Check password length"""
        length = len(password)
        if length >= 12:
            return 25, ["✓ Excellent length (12+ characters)"]
        elif length >= 8:
            return 15, ["✓ Good length (8+ characters)"]
        elif length >= 6:
            return 5, ["⚠ Fair length (6+ characters) - consider longer"]
        else:
            return 0, ["✗ Too short (less than 6 characters)"]

    def _check_character_variety(self, password):
        """Check for character variety"""
        score = 0
        feedback = []
        
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\?]', password))
        
        if has_lower:
            score += 5
            feedback.append("✓ Contains lowercase letters")
        else:
            feedback.append("✗ Missing lowercase letters")
            
        if has_upper:
            score += 5
            feedback.append("✓ Contains uppercase letters")
        else:
            feedback.append("✗ Missing uppercase letters")
            
        if has_digit:
            score += 5
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("✗ Missing numbers")
            
        if has_symbol:
            score += 10
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ Missing special characters")
            
        return score, feedback

    def _check_common_passwords(self, password):
        """Check against common passwords"""
        if password.lower() in self.common_passwords:
            return -20, ["✗ This is a commonly used password"]
        return 10, ["✓ Not in common password list"]

    def _check_patterns(self, password):
        """Check for common patterns"""
        penalty = 0
        feedback = []
        
        for pattern in self.common_patterns:
            if re.search(pattern, password.lower()):
                penalty += 5
                if 'repeated' in pattern or r'(.)\1{2,}' in pattern:
                    feedback.append("✗ Contains repeated characters")
                elif any(seq in pattern for seq in ['123', '012', '234']):
                    feedback.append("✗ Contains sequential numbers")
                elif any(seq in pattern for seq in ['abc', 'qwer', 'asdf']):
                    feedback.append("✗ Contains keyboard patterns or sequential letters")
        
        if penalty == 0:
            feedback.append("✓ No obvious patterns detected")
            return 10, feedback
        else:
            return -penalty, feedback

    def _calculate_entropy(self, password):
        """Calculate password entropy"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\?]', password):
            charset_size += 32
            
        if charset_size == 0:
            return 0
            
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)

    def _determine_strength(self, score):
        """Determine overall password strength"""
        if score >= 50:
            return "Very Strong"
        elif score >= 35:
            return "Strong"
        elif score >= 20:
            return "Medium"
        elif score >= 10:
            return "Weak"
        else:
            return "Very Weak"

    def check_breach(self, password):
        """Check if password appears in known breaches using Have I Been Pwned API"""
        try:
            # Hash the password
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query the API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                hashes = response.text.splitlines()
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)
                return False, 0
            else:
                return None, "API unavailable"
        except Exception as e:
            return None, f"Error checking breach: {str(e)}"

    def suggest_improvements(self, analysis):
        """Suggest improvements based on analysis"""
        suggestions = []
        
        if analysis['password_length'] < 12:
            suggestions.append("• Increase length to at least 12 characters")
            
        checks = analysis['checks']
        
        if checks['character_variety']['score'] < 25:
            char_feedback = checks['character_variety']['feedback']
            missing_types = [fb for fb in char_feedback if fb.startswith("✗")]
            if missing_types:
                suggestions.append("• Add missing character types: " + ", ".join([fb[2:] for fb in missing_types]))
        
        if checks['patterns']['score'] < 0:
            suggestions.append("• Avoid keyboard patterns, repeated characters, and sequential numbers/letters")
            
        if analysis['entropy'] < 50:
            suggestions.append("• Increase complexity to achieve higher entropy")
            
        suggestions.append("• Consider using a passphrase with 4-6 random words")
        suggestions.append("• Use a password manager to generate and store strong passwords")
        
        return suggestions

    def save_results(self, analysis, include_password_hash=False):
        """Save analysis results to file"""
        # Remove sensitive data for logging
        log_entry = analysis.copy()
        if not include_password_hash:
            log_entry.pop('password_hash', None)
        
        # Load existing data
        if os.path.exists(self.results_file):
            with open(self.results_file, 'r') as f:
                data = json.load(f)
        else:
            data = []
        
        data.append(log_entry)
        
        # Save updated data
        with open(self.results_file, 'w') as f:
            json.dump(data, f, indent=2)

    def display_results(self, analysis, breach_result=None):
        """Display formatted analysis results"""
        print("\n" + "="*60)
        print("           PASSWORD STRENGTH ANALYSIS REPORT")
        print("="*60)
        
        print(f"\n OVERALL STRENGTH: {analysis['strength']}")
        print(f" SCORE: {analysis['score']}/65")
        print(f" ENTROPY: {analysis['entropy']} bits")
        print(f" LENGTH: {analysis['password_length']} characters")
        
        if breach_result:
            breach_status, breach_count = breach_result
            print(f"\n  BREACH CHECK:")
            if breach_status is True:
                print(f"   ✗ Found in {breach_count:,} known data breaches - CHANGE IMMEDIATELY!")
            elif breach_status is False:
                print(f"   ✓ Not found in known data breaches")
            else:
                print(f"   ⚠ Could not check breaches: {breach_count}")
        
        print(f"\n DETAILED ANALYSIS:")
        for check_name, check_data in analysis['checks'].items():
            print(f"\n   {check_name.replace('_', ' ').title()}:")
            for feedback in check_data['feedback']:
                print(f"      {feedback}")
        
        print(f"\n RECOMMENDATIONS:")
        suggestions = self.suggest_improvements(analysis)
        for suggestion in suggestions:
            print(f"   {suggestion}")
        
        print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(description='Analyze password strength')
    parser.add_argument('--password', '-p', help='Password to analyze (not recommended for security)')
    parser.add_argument('--check-breach', '-b', action='store_true', help='Check against known data breaches')
    parser.add_argument('--save-results', '-s', action='store_true', help='Save results to file')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    
    args = parser.parse_args()
    
    analyzer = PasswordAnalyzer()
    
    if args.interactive or not args.password:
        print(" Password Strength Analyzer")
        print("Enter your password for analysis (input will be hidden):")
        password = getpass.getpass("Password: ")
    else:
        password = args.password
        print("  Warning: Passing passwords via command line arguments is not secure!")
    
    if not password:
        print("No password provided.")
        return
    
    print("\n Analyzing password...")
    analysis = analyzer.analyze_password(password)
    
    breach_result = None
    if args.check_breach:
        print(" Checking against known data breaches...")
        breach_result = analyzer.check_breach(password)
    
    analyzer.display_results(analysis, breach_result)
    
    if args.save_results:
        analyzer.save_results(analysis)
        print(f"\n Results saved to {analyzer.results_file}")

if __name__ == "__main__":
    main()