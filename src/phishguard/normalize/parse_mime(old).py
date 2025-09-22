"""
Email MIME parsing and conversion utilities

This module provides functions to convert EmailMessage objects to EmailRecord objects
for use by the PhishGuard analysis system.
"""

import re
from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple

from phishguard.schema import EmailRecord
from phishguard.features.extractors import extract_urls


def parse_email_to_record(email_msg: EmailMessage) -> EmailRecord:
    """
    Convert EmailMessage to EmailRecord for analysis
    
    Args:
        email_msg: Email message object from email parsing
        
    Returns:
        EmailRecord object ready for rule analysis
    """
    # Extract basic headers
    from_header = email_msg.get('From', '')
    reply_to_header = email_msg.get('Reply-To')
    subject = email_msg.get('Subject', '')
    
    # Parse From header to get display name and address
    from_display, from_addr = _parse_from_header(from_header)
    
    # Extract body content
    body_text, body_html = _extract_body_content(email_msg)
    
    # Extract URLs from body
    urls = extract_urls(body_text + (body_html or ''))
    url_display_pairs = [(url, url) for url in urls]  # Simplified - actual implementation might parse link text
    
    # Extract attachment information
    attachments = _extract_attachments(email_msg)
    
    # Convert headers to dict
    headers = dict(email_msg.items())
    
    # Parse authentication results (simplified)
    spf_pass, dkim_pass, dmarc_pass = _parse_auth_results(headers)
    
    return EmailRecord(
        from_display=from_display,
        from_addr=from_addr,
        reply_to_addr=reply_to_header,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        url_display_pairs=url_display_pairs,
        attachments=attachments,
        headers=headers,
        spf_pass=spf_pass,
        dkim_pass=dkim_pass,
        dmarc_pass=dmarc_pass
    )


def _parse_from_header(from_header: str) -> Tuple[str, str]:
    """Parse From header to extract display name and email address"""
    if not from_header:
        return '', ''
    
    # Handle format: "Display Name <email@domain.com>"
    match = re.match(r'^"?([^"<]*?)"?\s*<([^>]+)>$', from_header.strip())
    if match:
        display_name = match.group(1).strip()
        email_addr = match.group(2).strip()
        return display_name, email_addr
    
    # Handle format: "email@domain.com"
    if '@' in from_header:
        email_addr = from_header.strip()
        # Use local part as display name
        display_name = email_addr.split('@')[0]
        return display_name, email_addr
    
    # Fallback
    return from_header, from_header


def _extract_body_content(email_msg: EmailMessage) -> Tuple[str, Optional[str]]:
    """Extract text and HTML body content from email"""
    body_text = ''
    body_html = None
    
    if email_msg.is_multipart():
        for part in email_msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                content = part.get_content()
                if isinstance(content, str):
                    body_text += content
            elif content_type == 'text/html':
                content = part.get_content()
                if isinstance(content, str):
                    body_html = content
    else:
        content_type = email_msg.get_content_type()
        content = email_msg.get_content()
        if isinstance(content, str):
            if content_type == 'text/plain':
                body_text = content
            elif content_type == 'text/html':
                body_html = content
                # If only HTML, extract some text for analysis
                body_text = _html_to_text(content)
    
    return body_text, body_html


def _html_to_text(html_content: str) -> str:
    """Simple HTML to text conversion for analysis"""
    # Remove script and style elements
    html_content = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', html_content)
    # Decode HTML entities (basic)
    text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
    # Clean up whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _extract_attachments(email_msg: EmailMessage) -> List[str]:
    """Extract attachment filenames"""
    attachments = []
    
    if email_msg.is_multipart():
        for part in email_msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
    
    return attachments


def _parse_auth_results(headers: Dict[str, str]) -> Tuple[Optional[bool], Optional[bool], Optional[bool]]:
    """Parse authentication results from headers (simplified)"""
    spf_pass = None
    dkim_pass = None
    dmarc_pass = None
    
    # Look for Authentication-Results header
    auth_results = headers.get('Authentication-Results', '')
    
    if auth_results:
        # Simplified parsing - real implementation would be more robust
        if 'spf=pass' in auth_results.lower():
            spf_pass = True
        elif 'spf=fail' in auth_results.lower():
            spf_pass = False
            
        if 'dkim=pass' in auth_results.lower():
            dkim_pass = True
        elif 'dkim=fail' in auth_results.lower():
            dkim_pass = False
            
        if 'dmarc=pass' in auth_results.lower():
            dmarc_pass = True
        elif 'dmarc=fail' in auth_results.lower():
            dmarc_pass = False
    
    return spf_pass, dkim_pass, dmarc_pass
