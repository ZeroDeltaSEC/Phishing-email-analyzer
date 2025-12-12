"""
Scoring Engine Module
Intelligent weighted scoring system for final verdict
"""


class ScoringEngine:
    def __init__(self):
        # Weights for different components
        self.weights = {
            'authentication': 0.25,  # 25%
            'patterns': 0.25,        # 25%
            'urls': 0.25,            # 25%
            'attachments': 0.15,     # 15%
            'ai_confidence': 0.10    # 10%
        }
    
    def calculate_final_score(self, authentication, patterns, urls, attachments, ai_analysis):
        """
        Calculate final risk score (0-100) and verdict
        """
        scores = {}
        
        # 1. Authentication Score
        scores['authentication'] = self.score_authentication(authentication)
        
        # 2. Pattern Score
        scores['patterns'] = self.score_patterns(patterns)
        
        # 3. URL Score
        scores['urls'] = self.score_urls(urls)
        
        # 4. Attachment Score
        scores['attachments'] = self.score_attachments(attachments)
        
        # 5. AI Confidence Score
        scores['ai'] = self.score_ai_analysis(ai_analysis)
        
        # Calculate weighted total
        final_score = 0
        for component, score in scores.items():
            weight = self.weights.get(component, 0)
            final_score += score * weight
        
        # Round to integer
        final_score = int(round(final_score))
        
        # Determine verdict
        verdict = self.determine_verdict(final_score, scores)
        
        # Generate explanation
        explanation = self.generate_explanation(final_score, scores, verdict)
        
        return final_score, verdict, explanation
    
    def score_authentication(self, auth):
        """Score authentication results (0-100, higher = worse)"""
        score = 0
        
        # SPF
        if auth.get('spf') == 'FAIL':
            score += 35
        elif auth.get('spf') == 'SOFTFAIL':
            score += 20
        elif auth.get('spf') in ['NONE', 'UNKNOWN']:
            score += 15
        
        # DKIM
        if auth.get('dkim') == 'FAIL':
            score += 35
        elif auth.get('dkim') in ['NONE', 'UNKNOWN']:
            score += 15
        
        # DMARC
        if auth.get('dmarc') == 'FAIL':
            score += 30
        elif auth.get('dmarc') in ['NONE', 'UNKNOWN']:
            score += 10
        
        # Additional issues
        score += len(auth.get('issues', [])) * 10
        
        return min(score, 100)
    
    def score_patterns(self, patterns):
        """Score pattern detection results (0-100, higher = worse)"""
        score = 0
        
        # Urgent keywords
        score += len(patterns.get('urgent_keywords', [])) * 5
        
        # Suspicious patterns
        score += len(patterns.get('suspicious_patterns', [])) * 10
        
        # Brand impersonation
        if patterns.get('brand_impersonation'):
            score += 25
        
        # Typosquatting
        if patterns.get('typosquatting'):
            score += 25
        
        # Credential harvesting
        if patterns.get('credential_harvesting'):
            score += 30
        
        # HTML analysis
        html = patterns.get('html_analysis', {})
        if html.get('hidden_content'):
            score += 15
        if html.get('obfuscation'):
            score += 20
        if html.get('mismatched_links', 0) > 0:
            score += 10
        
        # Grammar issues
        score += patterns.get('grammar_issues', 0) * 5
        
        return min(score, 100)
    
    def score_urls(self, urls):
        """Score URL analysis results (0-100, higher = worse)"""
        if not urls:
            return 0
        
        score = 0
        high_risk_count = 0
        medium_risk_count = 0
        
        for url_result in urls:
            risk_level = url_result.get('risk_level', 'LOW')
            
            if risk_level == 'CRITICAL':
                score += 40
                high_risk_count += 1
            elif risk_level == 'HIGH':
                score += 25
                high_risk_count += 1
            elif risk_level == 'MEDIUM':
                score += 10
                medium_risk_count += 1
            elif risk_level == 'LOW':
                score += 2
        
        # Bonus penalty for multiple high-risk URLs
        if high_risk_count > 1:
            score += 20
        
        # Average the score if multiple URLs
        if len(urls) > 1:
            score = score // len(urls)
        
        return min(score, 100)
    
    def score_attachments(self, attachments):
        """Score attachment analysis results (0-100, higher = worse)"""
        if not attachments:
            return 0
        
        score = 0
        
        for attachment in attachments:
            analysis = attachment.get('analysis', {})
            risk_level = analysis.get('risk_level', 'LOW')
            
            if risk_level == 'CRITICAL':
                score += 50
            elif risk_level == 'HIGH':
                score += 30
            elif risk_level == 'MEDIUM':
                score += 15
            elif risk_level == 'LOW':
                score += 5
            
            # Additional penalties
            if analysis.get('macros_detected'):
                score += 20
            
            threats = analysis.get('threats', [])
            score += len(threats) * 5
        
        # Average if multiple attachments
        if len(attachments) > 1:
            score = score // len(attachments)
        
        return min(score, 100)
    
    def score_ai_analysis(self, ai_result):
        """Extract score from AI analysis"""
        if not ai_result or isinstance(ai_result, str) and 'error' in ai_result.lower():
            return 50  # Neutral score if AI failed
        
        # Try to extract risk score from AI output
        import re
        
        # Look for patterns like "RISK SCORE: 75" or "Score: 75/100"
        score_patterns = [
            r'risk\s*score[:\s]+(\d+)',
            r'score[:\s]+(\d+)',
            r'(\d+)/100',
            r'(\d+)%'
        ]
        
        ai_text = str(ai_result).lower()
        
        for pattern in score_patterns:
            match = re.search(pattern, ai_text)
            if match:
                try:
                    score = int(match.group(1))
                    return min(score, 100)
                except:
                    pass
        
        # Try to extract verdict
        if 'phishing' in ai_text or 'malicious' in ai_text:
            return 75
        elif 'suspicious' in ai_text:
            return 50
        elif 'safe' in ai_text or 'benign' in ai_text:
            return 20
        
        return 50  # Default neutral
    
    def determine_verdict(self, final_score, component_scores):
        """Determine final verdict based on score and components"""
        
        # Critical override conditions
        # If any single component is extremely high, override to MALICIOUS
        for component, score in component_scores.items():
            if score >= 90:
                return 'MALICIOUS'
        
        # If multiple components are high
        high_components = sum(1 for score in component_scores.values() if score >= 60)
        if high_components >= 3:
            return 'MALICIOUS'
        
        # Standard thresholds
        if final_score >= 60:
            return 'MALICIOUS'
        elif final_score >= 35:
            return 'SUSPICIOUS'
        else:
            return 'BENIGN'
    
    def generate_explanation(self, final_score, component_scores, verdict):
        """Generate human-readable explanation"""
        explanation_parts = []
        
        # Opening statement
        if verdict == 'MALICIOUS':
            explanation_parts.append("🚨 This email exhibits strong indicators of a phishing or malicious attack.")
        elif verdict == 'SUSPICIOUS':
            explanation_parts.append("⚠️  This email shows several suspicious characteristics that warrant caution.")
        else:
            explanation_parts.append("✓ This email appears to be legitimate with minimal risk indicators.")
        
        explanation_parts.append("")
        explanation_parts.append("Component Breakdown:")
        
        # Authentication
        auth_score = component_scores.get('authentication', 0)
        if auth_score > 50:
            explanation_parts.append(f"• Authentication: HIGH RISK ({auth_score}/100) - Failed email authentication checks")
        elif auth_score > 25:
            explanation_parts.append(f"• Authentication: MEDIUM RISK ({auth_score}/100) - Some authentication issues detected")
        else:
            explanation_parts.append(f"• Authentication: LOW RISK ({auth_score}/100) - Email authentication passed")
        
        # Patterns
        pattern_score = component_scores.get('patterns', 0)
        if pattern_score > 50:
            explanation_parts.append(f"• Content Patterns: HIGH RISK ({pattern_score}/100) - Multiple phishing indicators found")
        elif pattern_score > 25:
            explanation_parts.append(f"• Content Patterns: MEDIUM RISK ({pattern_score}/100) - Some suspicious patterns detected")
        else:
            explanation_parts.append(f"• Content Patterns: LOW RISK ({pattern_score}/100) - Normal content patterns")
        
        # URLs
        url_score = component_scores.get('urls', 0)
        if url_score > 50:
            explanation_parts.append(f"• URLs: HIGH RISK ({url_score}/100) - Suspicious or malicious URLs detected")
        elif url_score > 25:
            explanation_parts.append(f"• URLs: MEDIUM RISK ({url_score}/100) - Some URL concerns identified")
        elif url_score > 0:
            explanation_parts.append(f"• URLs: LOW RISK ({url_score}/100) - URLs appear normal")
        else:
            explanation_parts.append(f"• URLs: N/A - No URLs found")
        
        # Attachments
        att_score = component_scores.get('attachments', 0)
        if att_score > 50:
            explanation_parts.append(f"• Attachments: HIGH RISK ({att_score}/100) - Dangerous attachments detected")
        elif att_score > 25:
            explanation_parts.append(f"• Attachments: MEDIUM RISK ({att_score}/100) - Attachment concerns identified")
        elif att_score > 0:
            explanation_parts.append(f"• Attachments: LOW RISK ({att_score}/100) - Attachments appear safe")
        else:
            explanation_parts.append(f"• Attachments: N/A - No attachments")
        
        # AI Analysis
        ai_score = component_scores.get('ai', 0)
        explanation_parts.append(f"• AI Analysis: {ai_score}/100 confidence in assessment")
        
        # Recommendations
        explanation_parts.append("")
        explanation_parts.append("Recommendations:")
        
        if verdict == 'MALICIOUS':
            explanation_parts.append("• DO NOT click any links or open attachments")
            explanation_parts.append("• DO NOT reply to this email")
            explanation_parts.append("• Report this email to your security team")
            explanation_parts.append("• Delete this email immediately")
        elif verdict == 'SUSPICIOUS':
            explanation_parts.append("• Exercise caution with this email")
            explanation_parts.append("• Verify sender authenticity through alternate channel")
            explanation_parts.append("• Avoid clicking links or downloading attachments")
            explanation_parts.append("• Consider reporting to security team")
        else:
            explanation_parts.append("• Email appears legitimate, but always verify unexpected requests")
            explanation_parts.append("• Exercise normal caution with links and attachments")
        
        return '\n'.join(explanation_parts)
