# Import the iterate_emails function from the phishguard.ingestion.loaders module
from phishguard.ingestion.loaders import iterate_emails

# Iterate through emails returned by iterate_emails with an empty path (update as needed)
for origin, message in iterate_emails(r""):
    # Get the content type of the email message, default to empty string if not present, and convert to lowercase
    ctype = (message.get_content_type() or "").lower()
    # Print the origin and content type of the email message
    print(f"Origin: {origin}, Content-Type: {ctype}")
