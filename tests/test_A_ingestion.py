from phishguard.ingestion.loaders import iterate_emails
from typing import List, Optional, Tuple


for origin, message in iterate_emails(r"C:\Users\Cheston\Desktop\Krabby Patty Secret Recipe\SIT\INF 1002 - Programming Fundamentals\Python Project\emails\dev\ham"):
            ctype = (message.get_content_type() or "").lower()
            print(ctype)
