from __future__ import annotations

import os
import mailbox
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Generator, Tuple

PathLike = str | Path

class IngestionError(Exception):
    """When ingestion of email fails"""

def _parse_single_email(path: Path) -> EmailMessage:
    if not path.is_file():
        raise IngestionError(f"File not found: {path}")
    try:
        with path.open('rb') as file:
            return BytesParser(policy=policy.default).parse(file)
    except Exception:
        raw = path.read_bytes()
        if raw.startswith(b'From '):
            try:
                return mailbox.mboxMessage(raw, policy=policy.default)
            except Exception as e:
                raise IngestionError(f"Failed to parse mbox message from {path}: {e}")
        raise IngestionError(f"Failed to parse email from {path}")

def _parse_mbox(path: Path) -> Generator[Tuple[Path, EmailMessage], None, None]:
    if not path.is_file():
        raise IngestionError(f"Mbox file not found: {path}")
    try:
        mbox = mailbox.mbox(path, factory=lambda f: BytesParser(policy=policy.default).parse(f))
    except Exception as e:
        raise IngestionError(f"Failed to open mbox file {path}: {e}")
    for i, msg in enumerate(mbox):
        if not isinstance(msg, EmailMessage):
            raw = msg.as_bytes()
            try:
                msg = BytesParser(policy=policy.default).parsebytes(raw)
            except Exception as e:
                print(f"Skipping message {i+1} in {path} due to parse error: {e}")
                continue
        yield path.with_name(f"{path.name}::msg{i+1}"), msg

def _parse_file_or_mbox(path:Path) -> Generator[Tuple[Path, EmailMessage], None, None]:
    try:
        yield path, _parse_single_email(path)
        return
    except IngestionError:
        yield from _parse_mbox(path)
    return

def iterate_emails(source: PathLike) -> Generator[Tuple[Path, EmailMessage], None, None]:
    p = Path(source)
    if p.is_file():
        yield from _parse_file_or_mbox(p)
    elif p.is_dir():
        walker = os.walk(p)
        for dirpath, _dirnames, filenames in walker:
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if not fpath.is_file():
                    continue
                try:
                    yield from _parse_file_or_mbox(fpath)
                except IngestionError as e:
                    print(f"Skipping {fpath}: {e}")
                    continue
        return
    else:
        raise IngestionError(f"Path is neither file nor directory: {source}")
