# C: implement as provided earlier

import re

## Assuming normalizing is done, body content of email is ready.
def extract_urls_from_eml(body_content):
    urls = []   

    # This regex is to find URL in body_content
    # This regex matches common URL patterns (http/https, www, etc.)
    url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+~]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+' 
    found_urls = re.findall(url_pattern, body_content) 

    # Returns a list of URLs found in the body_content
    return urls