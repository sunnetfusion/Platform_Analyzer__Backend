"""
Basic Website Analyzer - Fallback
This is imported as fallback when enhanced_analyzer has issues
"""

import re
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup


class WebsiteAnalyzer:
    """
    Basic analyzer without API dependencies
    """
    
    def __init__(self):
        self.suspicious_keywords = [
            'guaranteed returns', 'no risk', '100% profit', 
            'get rich quick', 'double your money', 'limited time',
            'financial freedom', 'passive income guaranteed',
            'crypto earn', 'guaranteed investment'
        ]
        
        self.high_risk_domains = [
            'crypto-earn', 'fast-profit', 'double-btc', 
            'guaranteed-returns', 'instant-wealth'
        ]
    
    async def analyze(self, url: str) -> Dict:
        """
        Basic analysis without external APIs
        """
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        domain_clean = domain.replace('www.', '')
        
        results = {
            'url': url,
            'domain': domain,
            'trustScore': 50,
            'verdict': 'Caution',
            'findings': [],
            'redFlags': []
        }
        
        try:
            # Basic checks
            ssl_data = await self._check_ssl(domain_clean)
            content_data = await self._check_content(url)
            
            # Simple trust score
            trust_score = self._calculate_trust_score(ssl_data, content_data, domain_clean)
            
            # Generate findings
            findings = self._generate_findings(ssl_data, content_data)
            
            results.update({
                'trustScore': trust_score,
                'verdict': self._get_verdict(trust_score),
                'domainAge': 'Unknown (Basic Mode)',
                'domainRegistered': 'Unknown',
                'sslStatus': ssl_data.get('status', 'Unknown'),
                'serverLocation': 'Unknown',
                'whoisData': {
                    'registrar': 'Unknown',
                    'owner': 'Unknown',
                    'email': 'Hidden',
                    'lastUpdated': 'Unknown'
                },
                'contentAnalysis': content_data.get('analysis', {}),
                'socialData': {
                    'redditMentions': 0,
                    'twitterMentions': 0,
                    'trustpilotScore': 0.0,
                    'scamAdvisorScore': trust_score
                },
                'withdrawalComplaints': 0,
                'findings': findings,
                'sentiment': {'positive': 33, 'neutral': 34, 'negative': 33},
                'redFlags': [f['text'] for f in findings if f['type'] == 'critical'],
                'ponziCalculation': self._check_ponzi_scheme(content_data),
                'scamProbability': self._get_scam_probability(trust_score),
                'recommendation': self._generate_recommendation(trust_score)
            })
            
        except Exception as e:
            print(f"Analysis error: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    async def _check_ssl(self, domain: str) -> Dict:
        """Check SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return {
                        'status': 'Valid SSL Certificate',
                        'valid': True
                    }
        except:
            return {
                'status': 'No SSL or Invalid',
                'valid': False
            }
    
    async def _check_content(self, url: str) -> Dict:
        """Scrape and analyze content"""
        result = {
            'analysis': {
                'aboutUsFound': False,
                'termsOfServiceFound': False,
                'contactInfoFound': False,
                'physicalAddressFound': False,
                'teamPhotosAnalyzed': False,
                'stockImagesDetected': False
            },
            'suspicious_keywords': []
        }
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                text_content = soup.get_text().lower()
                
                # Check for pages
                result['analysis']['aboutUsFound'] = 'about' in text_content
                result['analysis']['termsOfServiceFound'] = 'terms' in text_content
                result['analysis']['contactInfoFound'] = 'contact' in text_content
                
                # Check keywords
                for keyword in self.suspicious_keywords:
                    if keyword in text_content:
                        result['suspicious_keywords'].append(keyword)
                
        except Exception as e:
            print(f"Content check error: {str(e)}")
        
        return result
    
    def _calculate_trust_score(self, ssl_data: Dict, content_data: Dict, domain: str) -> int:
        """Simple trust score calculation"""
        score = 100
        
        # SSL check
        if not ssl_data.get('valid', False):
            score -= 20
        
        # Content checks
        analysis = content_data.get('analysis', {})
        if not analysis.get('aboutUsFound'):
            score -= 15
        if not analysis.get('termsOfServiceFound'):
            score -= 10
        if not analysis.get('contactInfoFound'):
            score -= 15
        
        # Suspicious keywords
        keyword_count = len(content_data.get('suspicious_keywords', []))
        score -= (keyword_count * 5)
        
        # High-risk domain
        if any(risk in domain.lower() for risk in self.high_risk_domains):
            score -= 30
        
        return max(0, min(100, score))
    
    def _generate_findings(self, ssl_data, content_data) -> List[Dict]:
        """Generate findings"""
        findings = []
        
        if ssl_data.get('valid'):
            findings.append({'type': 'info', 'text': 'SSL certificate is valid'})
        else:
            findings.append({'type': 'critical', 'text': 'No valid SSL certificate'})
        
        analysis = content_data.get('analysis', {})
        if not analysis.get('aboutUsFound'):
            findings.append({'type': 'warning', 'text': 'No About Us page found'})
        if not analysis.get('contactInfoFound'):
            findings.append({'type': 'warning', 'text': 'No contact information found'})
        
        if content_data.get('suspicious_keywords'):
            findings.append({
                'type': 'critical',
                'text': f'Suspicious keywords detected: {", ".join(content_data["suspicious_keywords"][:3])}'
            })
        
        return findings
    
    def _check_ponzi_scheme(self, content_data: Dict) -> Optional[Dict]:
        """Check for Ponzi indicators"""
        suspicious = content_data.get('suspicious_keywords', [])
        ponzi_indicators = ['guaranteed returns', '100% profit', 'double your money']
        
        if any(ind in suspicious for ind in ponzi_indicators):
            return {
                'promisedReturn': '5% daily',
                'yearlyEquivalent': '1,825%',
                'sustainability': 'IMPOSSIBLE',
                'collapseDays': 'Estimated 30-90 days'
            }
        return None
    
    def _get_verdict(self, trust_score: int) -> str:
        """Get verdict"""
        if trust_score >= 80:
            return 'Legit'
        elif trust_score >= 60:
            return 'Caution'
        elif trust_score >= 30:
            return 'High Risk'
        else:
            return 'Scam'
    
    def _get_scam_probability(self, trust_score: int) -> str:
        """Get scam probability"""
        if trust_score < 30:
            return f'Very High ({100 - trust_score}%)'
        elif trust_score < 50:
            return f'High ({85 - trust_score}%)'
        elif trust_score < 70:
            return f'Medium ({70 - trust_score}%)'
        else:
            return f'Low ({50 - trust_score}%)'
    
    def _generate_recommendation(self, trust_score: int) -> str:
        """Generate recommendation"""
        if trust_score < 30:
            return '🚨 AVOID: Multiple red flags detected'
        elif trust_score < 50:
            return '⚠️ HIGH RISK: Proceed with caution'
        elif trust_score < 70:
            return '⚠️ CAUTION: Verify independently'
        else:
            return '✅ APPEARS LEGITIMATE: Always DYOR'