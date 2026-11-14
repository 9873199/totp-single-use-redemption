import sqlite3,datetime,sys
from pathlib import Path
from pyotp import TOTP,consume_totp,ReplayedOTPError
from pyotp.contrib.sqlite_store import SQLiteTOTPStore
from totp_oracle import otp,secret_text
file=Path("recorded-consumption.db")
assert not file.exists(),"Fresh demo database required"
c=sqlite3.connect(file);store=SQLiteTOTPStore(c)
value=TOTP(secret_text());when=datetime.datetime.fromtimestamp(41*30,datetime.timezone.utc)
def use(generation):return consume_totp(value,otp(41),"review",generation,store,for_time=when)
print("Offline verification / generated test seed")
print("First consume counter:",use(7))
try:use(7)
except ReplayedOTPError:print("Same-generation replay: rejected")
print("Active row before:",c.execute("SELECT key_generation,last_timecode FROM totp_consumption").fetchone())
print("No key-activation step performed")
print("Larger generation consume result:",use(8))
print("Active row after:",c.execute("SELECT key_generation,last_timecode FROM totp_consumption").fetchone())
print("Active-generation confirmation: incomplete")
c.close();sys.exit(1)
