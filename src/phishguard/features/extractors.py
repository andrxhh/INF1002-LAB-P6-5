    # C: implement as provided earlier

import re
from bs4 import BeautifulSoup

## Assuming normalizing is done, body content of email is ready.
def extract_urls(body_content):
    urls = []   

    # This regex is to find URL in body_content
    # This regex matches common URL patterns (http/https, www, etc.)
    url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+~]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+' 
    found_urls = re.findall(url_pattern, body_content) \
    # Returns a list of URLs found in the body_content
    return urls





# WORK IN PROGRESS
def extract_email_url_pairs(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    print(soup)
    url_pairs = []

    for a_tag in soup.find_all('a', href=True):
        displayed_text = a_tag.get_text(strip=True)
        actual_url = a_tag['href']
        
        # Only keep if both parts exist and are URLs
        if displayed_text and actual_url.startswith(('http://', 'https://')):
            url_pairs.append((displayed_text, actual_url))

    return url_pairs


html_email = '''
<p>Hello user,</p>
<p>Click <a href="http://phishing.com/login">https://paypal.com</a> to access your account.</p>
<p>Visit our <a href="https://company.com">website</a> for more info.</p>
'''

pairs = extract_email_url_pairs(html_email)
for display, actual in pairs:
    print(f"Displayed: {display} -> Actual: {actual}")