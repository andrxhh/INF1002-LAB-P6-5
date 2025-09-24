from phishguard.ingestion.loaders import iterate_emails
from phishguard.normalize.parse_mime import normalize_header, extract_body, decode_address
from phishguard.features.extractors import extract_urls, extract_url_pairs, extract_attachments
from phishguard.schema.classes import EmailRecord

record = []
for origin, message in iterate_emails(r"C:\Users\Cheston\Desktop\Krabby Patty Secret Recipe\SIT\INF 1002 - Programming Fundamentals\Python Project\emails\dev\spam\00061.bec763248306fb3228141491856ed216"):
    header = normalize_header(message)
    from_display, from_addr, reply_to_addr = decode_address(message)
    body_text, body_html = extract_body(message)
    urls, url_pairs = extract_urls(body_text, body_html)
    attachments = extract_attachments(message)
    spf, dkim, dmarc = None, None, None  # Placeholder for actual SPF, DKIM, DMARC checks

    rec = EmailRecord(
        from_display=from_display,
        from_addr=from_addr,
        reply_to_addr=reply_to_addr,
        subject=header.get('subject', ''),
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        url_display_pairs=url_pairs,
        attachments=attachments,
        headers=header,
        spf_pass=spf,
        dkim_pass=dkim,
        dmarc_pass=dmarc
    )

    record.append(rec)
print(record)