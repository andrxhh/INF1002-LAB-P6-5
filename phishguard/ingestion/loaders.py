# A: implement as provided earlier

from email.parser import BytesParser
from email import policy


class IngestionError(Exception):
    print("gg lor ingestion fail") #Temporary Filler


def load_eml():
    
    file_path = "enter file path here e.g. C:/filepath/file or ../../../filepath/file" #Temporary "input" of .eml
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            return msg
    except:
        raise IngestionError

