from phishguard.ingestion.loaders import iterate_emails

for origin, message in iterate_emails(""):
    print(origin, message["Subject"])