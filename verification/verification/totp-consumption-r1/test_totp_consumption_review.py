import sqlite3,threading,datetime
import pytest,pyotp
from pyotp import consume_totp
from pyotp.replay import InvalidOTPError,ReplayedOTPError,StaleKeyGenerationError,TOTPStorageError
from pyotp.contrib.sqlite_store import SQLiteTOTPStore
from totp_oracle import otp,secret_text,collision
class Recorder:
 def __init__(self,error=None):self.calls=[];self.error=error
 def consume(self,*args):
  self.calls.append(args)
  if self.error:raise self.error
def generator(digits=6):return pyotp.TOTP(secret_text(),digits=digits)
def consume(store,counter=41,generation=7,account='review',code=None,window=0,digits=6):
 return consume_totp(generator(digits),otp(counter,digits) if code is None else code,account,generation,store,for_time=datetime.datetime.fromtimestamp(counter*30,datetime.timezone.utc),valid_window=window)
def make_store(path):
 c=sqlite3.connect(path);s=SQLiteTOTPStore(c);return c,s
def test_invalid_code_never_touches_store():
 s=Recorder();
 with pytest.raises(InvalidOTPError):consume(s,code='bad-input')
 assert s.calls==[]
@pytest.mark.parametrize('counter',[0,1,2,41])
def test_real_hmac_counter_single_call_and_zero(counter):
 s=Recorder();result=consume(s,counter=counter,window=2)
 assert result==counter and result is not False
 assert s.calls==[('review',7,counter)]
def test_window_collision_maximum_and_no_replay_fallback():
 center,code,counters=collision();s=Recorder();result=consume(s,counter=center,code=code,window=2,digits=1)
 assert result==max(counters) and s.calls==[('review',7,max(counters))]
 s=Recorder(ReplayedOTPError('review',7,max(counters)))
 with pytest.raises(ReplayedOTPError):consume(s,counter=center,code=code,window=2,digits=1)
 assert len(s.calls)==1 and s.calls[0][2]==max(counters)
@pytest.mark.parametrize('error',[RuntimeError('offline store unavailable'),sqlite3.OperationalError('offline injected I/O failure'),TOTPStorageError('offline commit failure')])
def test_store_failure_never_success(error):
 s=Recorder(error)
 with pytest.raises(TOTPStorageError):consume(s)
 assert len(s.calls)==1
def test_distinct_domain_codes():
 errors=[InvalidOTPError(),ReplayedOTPError('review',7,41),StaleKeyGenerationError('review',7,41,8),TOTPStorageError('offline')]
 assert len({e.code for e in errors})==4
@pytest.mark.parametrize('counter',[0,41])
def test_sqlite_same_counter_replay(tmp_path,counter):
 c,s=make_store(tmp_path/'state.db')
 try:
  assert consume(s,counter)==counter
  with pytest.raises(ReplayedOTPError):consume(s,counter)
 finally:c.close()
def test_clock_rollback_and_independent_accounts(tmp_path):
 c,s=make_store(tmp_path/'state.db')
 try:
  consume(s,41)
  with pytest.raises(ReplayedOTPError):consume(s,40)
  assert consume(s,40,account='another')==40
  assert consume(s,42)==42
 finally:c.close()
def seed(c,generation=7,counter=40):
 c.execute('INSERT INTO totp_consumption VALUES (?,?,?)',('review',generation,counter));c.commit()
def test_old_generation_rejected(tmp_path):
 c,s=make_store(tmp_path/'state.db');seed(c)
 try:
  with pytest.raises(StaleKeyGenerationError):consume(s,generation=6)
  assert c.execute('SELECT key_generation,last_timecode FROM totp_consumption').fetchone()==(7,40)
 finally:c.close()
@pytest.mark.parametrize('presented',[8,100])
def test_not_activated_generation_cannot_replace_active_generation(tmp_path,presented):
 c,s=make_store(tmp_path/'state.db');seed(c)
 try:
  observed=None
  try:observed=consume(s,generation=presented)
  except StaleKeyGenerationError:pass
  state=c.execute('SELECT key_generation,last_timecode FROM totp_consumption').fetchone()
  print('active_before',7,'presented',presented,'result',observed,'state_after',state)
  assert observed is None and state==(7,40),'Consume must confirm active generation, not authorize generation replacement'
 finally:c.close()
def test_explicit_rotation_then_new_generation_and_zero(tmp_path):
 c,s=make_store(tmp_path/'state.db');seed(c)
 try:
  c.execute('UPDATE totp_consumption SET key_generation=8,last_timecode=-1 WHERE account_id=?',('review',));c.commit()
  with pytest.raises(StaleKeyGenerationError):consume(s,generation=7)
  assert consume(s,counter=0,generation=8)==0
 finally:c.close()
class GatedConnection:
 def __init__(self,c):self.c=c;self.armed=False;self.ready=threading.Event();self.release=threading.Event()
 def execute(self,*args):return self.c.execute(*args)
 def rollback(self):return self.c.rollback()
 def commit(self):
  if self.armed:
   self.ready.set();assert self.release.wait(5)
  return self.c.commit()
def test_two_connections_deterministic_commit_boundary(tmp_path):
 path=tmp_path/'race.db';a=sqlite3.connect(path,check_same_thread=False);gate=GatedConnection(a);sa=SQLiteTOTPStore(gate);b,sb=make_store(path);sb=SQLiteTOTPStore(b,busy_timeout=30);gate.armed=True;out=[]
 def first():
  try:out.append(consume(sa))
  except BaseException as e:out.append(e)
 t=threading.Thread(target=first);t.start()
 try:
  assert gate.ready.wait(5)
  assert b.execute('SELECT * FROM totp_consumption').fetchall()==[]
  with pytest.raises(TOTPStorageError):consume(sb)
 finally:gate.release.set();t.join(5)
 try:
  assert not t.is_alive() and out==[41]
  with pytest.raises(ReplayedOTPError):consume(sb)
  assert b.execute('SELECT key_generation,last_timecode FROM totp_consumption').fetchall()==[(7,41)]
 finally:a.close();b.close()
class FailingCommit:
 def __init__(self,c):self.c=c;self.armed=False
 def execute(self,*args):return self.c.execute(*args)
 def rollback(self):return self.c.rollback()
 def commit(self):
  if self.armed:raise sqlite3.OperationalError('reviewer forced commit failure')
  self.c.commit()
def test_commit_failure_does_not_persist_or_return_success(tmp_path):
 path=tmp_path/'fail.db';c=sqlite3.connect(path);wrapper=FailingCommit(c);s=SQLiteTOTPStore(wrapper);wrapper.armed=True
 try:
  with pytest.raises(TOTPStorageError):consume(s)
  with sqlite3.connect(path) as other:assert other.execute('SELECT * FROM totp_consumption').fetchall()==[]
 finally:c.close()
def test_no_seed_or_code_columns_or_logs(tmp_path,caplog):
 c,s=make_store(tmp_path/'state.db')
 try:
  consume(s);names=[r[1] for r in c.execute('PRAGMA table_info(totp_consumption)')]
  assert names==['account_id','key_generation','last_timecode']
  assert secret_text() not in caplog.text and otp(41) not in caplog.text
 finally:c.close()
def test_constant_time_compare_entry_used(monkeypatch):
 old=pyotp.utils.strings_equal;calls=[]
 def counted(a,b):calls.append(1);return old(a,b)
 monkeypatch.setattr(pyotp.utils,'strings_equal',counted);consume(Recorder());assert calls
def test_legacy_stateless_verification_unchanged():
 g=generator();date=datetime.datetime.fromtimestamp(41*30,datetime.timezone.utc)
 assert g.verify(otp(41),for_time=date) and g.verify(otp(41),for_time=date)
 assert g.verify_and_get_timecode(otp(41),for_time=date)==41
