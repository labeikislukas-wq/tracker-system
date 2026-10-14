"""One-time Apple login run from GitHub Actions (workflow "Apple login"), no PC needed.

Same result as app.setup_apple_login (the session is saved to the database with
save_account), but non-interactive:

1. The Apple ID and password come from the repository secrets APPLE_ID and
   APPLE_PASSWORD.
2. Apple is asked to send the 2FA code (SMS by default, or "device").
3. The job then waits up to 10 minutes for the code. The code is handed over by
   the separate workflow "Apple code", which stores it in app_state
   ('apple_2fa_code'); this job takes it (and deletes the row), submits it and
   saves the session.

Nothing about the account (e-mail, phone number, session) is printed: the
Actions log may be visible to others.
"""

from __future__ import annotations

import os
import sys
import time

from findmy import (
    AppleAccount,
    LoginState,
    SmsSecondFactorMethod,
    TrustedDeviceSecondFactorMethod,
)

from .apple_account import anisette_provider, save_account
from .db import SessionLocal
from . import models  # noqa: F401  (register tables)
from .models import AppState

CODE_KEY = "apple_2fa_code"
WAIT_SECONDS = 600


def _take_code(db) -> str | None:
    db.expire_all()
    row = db.get(AppState, CODE_KEY)
    if row is None:
        return None
    code = (row.value or "").strip()
    db.delete(row)
    db.commit()
    return code or None


def main() -> int:
    email = os.environ.get("APPLE_ID", "").strip()
    password = os.environ.get("APPLE_PASSWORD", "")
    if not email or not password:
        print("::error::Add the repository secrets APPLE_ID and APPLE_PASSWORD first "
              "(Settings -> Secrets and variables -> Actions).")
        return 1
    want = (os.environ.get("TWOFA_METHOD") or "sms").strip().lower()

    db = SessionLocal()
    try:
        _take_code(db)  # a stale code from an earlier attempt must never be used
        acc = AppleAccount(anisette_provider())
        state = acc.login(email, password)
        if state == LoginState.REQUIRE_2FA:
            methods = acc.get_2fa_methods()
            sms = [m for m in methods if isinstance(m, SmsSecondFactorMethod)]
            dev = [m for m in methods if isinstance(m, TrustedDeviceSecondFactorMethod)]
            pick = (dev if want == "device" else sms) or sms or dev or list(methods)
            if not pick:
                print("::error::Apple offered no way to send a 2FA code.")
                return 1
            method = pick[0]
            method.request()
            where = "by SMS" if isinstance(method, SmsSecondFactorMethod) else "to the Apple devices"
            print(f"Apple sent the 2FA code {where}. Now run the workflow 'Apple code' "
                  "with that 6-digit code (this job waits 10 minutes).", flush=True)

            code = None
            deadline = time.time() + WAIT_SECONDS
            while time.time() < deadline:
                code = _take_code(db)
                if code:
                    break
                time.sleep(5)
            if not code:
                print("::error::No code arrived within 10 minutes. Run 'Apple login' again.")
                return 1
            try:
                method.submit(code)
            except Exception as e:  # noqa: BLE001
                print(f"::error::Apple refused the code ({type(e).__name__}). Run 'Apple login' again.")
                return 1

        if acc.login_state != LoginState.LOGGED_IN:
            print(f"::error::Login did not complete (state: {acc.login_state}).")
            return 1
        save_account(db, acc)
        print("Logged in. The Apple session is saved in Supabase; the poller can run.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
