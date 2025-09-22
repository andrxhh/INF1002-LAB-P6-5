from phishguard.normalize.parse_mime import normalize_header, extract_body, decode_address
from phishguard.ingestion.loaders import iterate_emails
from email.message import EmailMessage

for origin, message in iterate_emails(r"C:\Users\Cheston\Desktop\Krabby Patty Secret Recipe\SIT\INF 1002 - Programming Fundamentals\Python Project\emails\dev\ham\00001.7c53336b37003a9286aba55d2945844c"):
    print(normalize_header(message))
    body_text, html_text = extract_body(message)
    print(f"Body Text: {body_text[:100]}...")  # Print first 100 characters of body text
    if html_text:
        print(f"HTML Text: {html_text[:100]}...")  # Print first 100 characters of HTML text if available
    print(decode_address(message))