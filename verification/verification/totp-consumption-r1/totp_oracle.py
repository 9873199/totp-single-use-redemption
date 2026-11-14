"""Independent HMAC-TOTP counters for collision and epoch acceptance."""
import base64,hashlib,hmac,struct
TEST_SEED=bytes(range(1,21))
def otp(counter,digits=6):
 value=hmac.new(TEST_SEED,struct.pack('>Q',counter),hashlib.sha1).digest()
 offset=value[-1]&15;binary=int.from_bytes(value[offset:offset+4],'big')&0x7fffffff
 return str(binary%(10**digits)).zfill(digits)
def secret_text():
 return base64.b32encode(TEST_SEED).decode('ascii')
def collision():
 for center in range(50,1000):
  groups={}
  for c in range(center-2,center+3):groups.setdefault(otp(c,1),[]).append(c)
  for code,counters in groups.items():
   if len(counters)>1:return center,code,counters
 raise AssertionError('No test collision')
if __name__=='__main__':
 import pyotp
 generator=pyotp.TOTP(secret_text())
 assert all(generator.generate_otp(c)==otp(c) for c in (0,1,2,99,1234))
 center,code,counters=collision()
 short=pyotp.TOTP(secret_text(),digits=1)
 assert len(counters)>1 and all(short.generate_otp(c)==code for c in counters)
 print('TOTP fixture controls PASS: independent HMAC calculation, epoch counter0 and real short-code window collision. No seed or OTP values logged.')
