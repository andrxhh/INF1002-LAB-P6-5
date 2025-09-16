# rule: whitelist
import os
import re


## EXAMPLE USAGE OF FUNCTION
# emailaddr = "hello@google.com"
# check_domain_whitelist("hello@google.com") 

def check_domain_whitelist(emailaddr):

    # Regex to search the email domain
    sender_domain = re.search(r'@([\w.-]+)', emailaddr).group(1) 
    try: 
        with open(os.getcwd()+ '\\phishguard\\lists\\domain_whitelist.txt') as wlist: ## Uncertain line subject to change
            
            email_list = wlist.read().splitlines()
            if sender_domain is not None: # Handles the possibility where Regex does not find any matches

                # Compares domain in whitelist WITH domain of sender's email address
                for item in email_list: 
                    if sender_domain == item:
                        print("This email is legitimate as it is in the whitelist") # FILLER LINES, need to remove as proj develops
                        return
                    else:
                        print("Goes into rules-based checks")  # FILLER LINES, need to remove as proj develops
                        return
            else:
                print("Goes into rules-based checks")  # FILLER LINES, need to remove as proj develops
    except:
        return 
