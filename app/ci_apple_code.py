"""Hand the Apple 2FA code to the waiting "Apple login" job (workflow "Apple code").

Stores the code in app_state ('apple_2fa_code'); app.ci_apple_login takes it
within a few seconds and deletes the row. The code is masked in the log.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from .db import SessionLocal
from . import models  # noqa: F401  (register tables)
from .models import AppState

CODE_KEY = "apple_2fa_code"


def main() -> int:
    code = "".join(ch for ch in os.environ.get("CODE_RAW", "") if ch.isdigit())
    if code:
        print(f"::add-mask::{code}", flush=True)
    if len(code) != 6:
        print("::error::Enter the 6-digit code Apple sent (digits only).")
        return 1
    db = SessionLocal()
    try:
        row = db.get(AppState, CODE_KEY)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if row is None:
            db.add(AppState(key=CODE_KEY, value=code, updated_at=now))
        else:
            row.value = code
            row.updated_at = now
        db.commit()
    finally:
        db.close()
    print("Code handed over. The 'Apple login' run finishes the sign-in within a few seconds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
