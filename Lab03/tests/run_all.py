#!/usr/bin/env python3
"""Reproduce the handout cases. Expected arithmetic uses Python, not program output."""
import argparse, hashlib, itertools, json, os, re, secrets, shutil, subprocess, sys, tempfile, time, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--exe',default=str(ROOT/'build'/('lab03.exe' if os.name=='nt' else 'lab03')));parser.add_argument('--openssl',default=os.environ.get('OPENSSL_CLI','openssl'));parser.add_argument('--keep-work',action='store_true');args=parser.parse_args()
EXE=Path(args.exe).resolve();SSL=args.openssl
WORK=Path(tempfile.mkdtemp(prefix='work-',dir=ROOT/'tests'));LOG=ROOT/'tests'/'results';LOG.mkdir(exist_ok=True)
records=[];details=[];checks=0

def run(cmd,code=0,contains=None,binary=False,log=True):
 global checks
 env=os.environ.copy();env['TEMP']=str(WORK);env['TMP']=str(WORK)
 p=subprocess.run([str(c) for c in cmd],capture_output=True,timeout=180,env=env)
 out=p.stdout.decode('utf8','replace');err=p.stderr.decode('utf8','replace')
 if log:details.append('$ '+' '.join(map(str,cmd))+'\nexit='+str(p.returncode)+'\nstdout:\n'+out+'\nstderr:\n'+err)
 assert p.returncode==code,f'exit {p.returncode}, expected {code}: {cmd}\n{out}\n{err}'
 if contains is not None:assert contains in out+err,f'missing {contains!r}: {out} {err}'
 checks+=1
 return p.stdout if binary else out.strip()

def cli(*cmd,code=0,contains=None):return run([EXE,*cmd],code,contains)
def ssl(*cmd,**kw):return run([SSL,*cmd],**kw)
def eq(a,b):
 global checks
 assert a==b,f'values differ: {str(a)[:120]} != {str(b)[:120]}';checks+=1

def group(name,fn):
 start=time.monotonic();before=checks
 try:fn();status='PASS';reason=''
 except Exception as e:status='FAIL';reason=str(e);details.append('FAIL '+name+': '+reason)
 records.append(dict(id=name,status=status,checks=checks-before,seconds=round(time.monotonic()-start,3),reason=reason))
 print(f'[{status}] {name}',flush=True)

def no_plain(path):
 eq(path.exists(),False);eq(Path(str(path)+'.part').exists(),False)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def mutated(src,name,offset,value=None,xor=1):
 b=bytearray(Path(src).read_bytes());b[offset]=b[offset]^xor if value is None else value;p=WORK/name;p.write_bytes(b);return p

def negative(command,key,path,code,name):
 out=WORK/(name+'.plain');cli(command,'--priv',key,'--in',path,'--out',out,code=code,contains='decryption failed' if code==4 else None);no_plain(out)

k=ROOT/'keys';k.mkdir(exist_ok=True);wrong=WORK/'wrong';small=WORK/'small'
try:
 group('BUILD-version',lambda:cli('version',contains='OpenSSL'))
 vectors=[('A-T1','mod-exp',[7,13,33],pow(7,13,33),0),('A-T2','gcd',[252,105],21,0),('A-T3','mod-inverse',[7,33],pow(7,-1,33),0),('A-T4','mod-inverse',[6,33],'no inverse: gcd(a,m) = 3',4),('A-T5','mod-sub',[3,5,7],5,0),('A-T6','mod-add',[2**64-1,1,2**64+13],2**64,0),('A-T7','mod-exp',[123456789012345678901234567890,65537,2**127-1],pow(123456789012345678901234567890,65537,2**127-1),0),('A-T8','mod-inverse',[65537,2**127-1],pow(65537,-1,2**127-1),0)]
 for name,op,nums,expected,code in vectors:
  def test(op=op,nums=nums,expected=expected,code=code):
   s=cli(op,*map(str,nums),code=code,contains=str(expected) if code else None)
   if code==0:eq(s,str(expected))
  group(name,test)
 def a_invalid():
  for c in [('mod-add','1','2','0'),('mod-exp','-3','2','5'),('gcd','12a','4'),('gcd','','4'),('gcd','1'*10001,'4'),('mod-inverse','1','1'),('gcd','+2','4'),('gcd',' 2','4')]:cli(*c,code=1)
  eq(cli('gcd','0','0'),'0');eq(cli('mod-add','200','200','257','--hex').upper().lstrip('0'),'8F')
 group('A-T9',a_invalid)
 def b1():
  s=cli('rsa-params','--bits','512');assert 'FAIL' not in s;assert len(re.findall('PASS',s))>=4;sizes=re.findall(r'(?:n bits|bits.*n|n bit length)[^\d]*(\d+)',s,re.I)
  if sizes:assert int(sizes[0]) in (511,512)
 group('B-T1',b1)
 def b2():
  cli('keygen','--bits','3072','--out-dir',k,'--force');cli('keygen','--bits','3072','--out-dir',wrong);cli('keygen','--bits','2048','--out-dir',small)
  for ext in ['pem','der']:ssl('pkey','-in',k/('private.'+ext),'-inform',ext.upper(),'-check','-noout')
 group('B-T2',b2)
 pub=k/'public.pem';priv=k/'private.pem'
 group('B-T3',lambda:[cli('key-check','--priv',k/('private.'+a),'--pub',k/('public.'+b),contains='MATCH') for a,b in itertools.product(['pem','der'],repeat=2)])
 group('B-T4',lambda:cli('key-check','--priv',wrong/'private.pem','--pub',pub,code=4,contains='MISMATCH'))
 def b5():
  for typ in ['public','private']:
   a=WORK/(typ+'.der');b=WORK/(typ+'.pem');cli('key-convert','--type',typ,'--in',k/(typ+'.pem'),'--out',a,'--outform','DER');cli('key-convert','--type',typ,'--in',a,'--out',b,'--outform','PEM');eq(b.read_bytes(),(k/(typ+'.pem')).read_bytes())
 group('B-T5',b5)
 def b6():
  p=cli('key-info','--pub',pub);d=cli('key-info','--pub',k/'public.der');eq(p,d);eq(sha(k/'public.der') in p.lower(),True)
  der=ssl('pkey','-pubin','-in',pub,'-outform','DER',binary=True,log=False);eq(der,(k/'public.der').read_bytes())
 group('B-T6',b6)
 def b7():
  trunc=WORK/'trunc.der';trunc.write_bytes((k/'public.der').read_bytes()[:32]);tail=WORK/'tail.der';tail.write_bytes((k/'public.der').read_bytes()+b'x')
  weak=WORK/'weak.pem';pkcs1=WORK/'pkcs1.der';ec=WORK/'ec.pem'
  ssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:1024','-out',WORK/'weak-private.pem');ssl('pkey','-in',WORK/'weak-private.pem','-pubout','-out',weak)
  ssl('rsa','-in',priv,'-RSAPublicKey_out','-outform','DER','-out',pkcs1)
  ssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',WORK/'ec-private.pem');ssl('pkey','-in',WORK/'ec-private.pem','-pubout','-out',ec)
  for bad in [trunc,tail,weak,pkcs1,ec,priv]:cli('key-info','--pub',bad,code=3)
  cli('key-check','--priv',pub,'--pub',pub,code=3)
 group('B-T7',b7)
 cases=[('000001',1,3,'000001',0),('000001',1,1,'01',0),('0100',256,2,'0100',0),('0100',256,1,'',1),('00ff00',65280,3,'00ff00',0),('',0,2,'0000',0)]
 for j,(hx,num,width,expect,code) in enumerate(cases,1):
  def ct(hx=hx,num=num,width=width,expect=expect,code=code):
   eq(cli('os2ip','--hex',hx),str(num));out=cli('i2osp','--int',str(num),'--len',str(width),code=code)
   if not code:eq(out.lower(),expect)
  group('C-T'+str(j),ct)
 def c7():
  b=b'\x00'+secrets.token_bytes(31);n=int(cli('os2ip','--hex',b.hex()));eq(n,int.from_bytes(b,'big'));eq(cli('i2osp','--int',str(n),'--len','32').lower(),b.hex())
 group('C-T7',c7)
 def c8():eq(pow(65,17,3233),2790);eq(pow(2790,2753,3233),65);cli('task-c-all',contains='ALL CHECKS PASSED')
 group('C-T8',c8)
 def c9():eq(pow(6,17,3233),824);eq(pow(7,17,3233),2369);eq((824*2369)%3233,2557);eq(pow(2557,2753,3233),42)
 group('C-T9',c9)
 group('C-T10',lambda:cli('raw-rsa','--bits','512',contains='ALL CHECKS PASSED'))
 group('C-T11',lambda:cli('oaep-demo','--pub',pub,'--priv',priv,contains='ALL CHECKS PASSED'))
 samples=WORK/'samples';samples.mkdir();(samples/'empty').write_bytes(b'');(samples/'text.txt').write_text('Lab 03 - Xin chào Việt Nam.\n',encoding='utf8');(samples/'image.png').write_bytes(bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b49444154789c636000020000050001a5f645400000000049454e44ae426082'))
 (samples/'sample.pdf').write_bytes(b'%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n')
 with zipfile.ZipFile(samples/'sample.zip','w') as z:z.write(samples/'text.txt','text.txt')
 with (samples/'random50MiB.bin').open('wb') as f:
  for i in range(50):f.write(secrets.token_bytes(1024*1024))
 plain=samples/'text.txt';dpack=WORK/'base-d.l2pk'
 def roundtrip(enc,dec,pk,sk,src,stem):
  package=WORK/(stem+'.l2pk');out=WORK/(stem+'.recovered');cli(enc,'--pub',pk,'--in',src,'--out',package);cli(dec,'--priv',sk,'--in',package,'--out',out);eq(sha(src),sha(out));return package
 group('D-T1',lambda:[roundtrip('encrypt','decrypt',pub,priv,f,'d-'+f.name) for f in sorted(samples.iterdir())])
 group('D-T2',lambda:[roundtrip('encrypt','decrypt',k/('public.'+a),k/('private.'+b),plain,'d-matrix-'+a+b) for a,b in itertools.product(['pem','der'],repeat=2)])
 def d3():
  cli('encrypt','--pub',pub,'--in',plain,'--out',dpack);second=WORK/'d-second.l2pk';cli('encrypt','--pub',pub,'--in',plain,'--out',second);assert sha(dpack)!=sha(second)
 group('D-T3',d3)
 for name,off in [('D-T4',414),('D-T5',-1)]:group(name,lambda name=name,off=off:negative('decrypt',priv,mutated(dpack,name,off),4,name))
 group('D-T6',lambda:[negative('decrypt',priv,mutated(dpack,'D-T6-'+str(off),off),4,'d6-'+str(off)) for off in [394,15]])
 group('D-T7',lambda:[negative('decrypt',priv,mutated(dpack,'D-T7-'+str(off),off),3,'d7-'+str(off)) for off in [6,4,0]])
 def d8():
  b=dpack.read_bytes()
  for name,data in [('truncated',b[:-1]),('extra',b+b'\xa5'),('huge',b[:406]+(2**63).to_bytes(8,'big')+b[414:])]:
   p=WORK/('d-'+name);p.write_bytes(data);negative('decrypt',priv,p,3,'d8-'+name)
 group('D-T8',d8)
 group('D-T9',lambda:negative('decrypt',wrong/'private.pem',dpack,4,'d9'))
 group('D-T10',lambda:negative('decrypt',small/'private.pem',dpack,3,'d10'))
 # Independent implementation validates the byte-level package, not another student's work.
 def d_reference():
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  b=dpack.read_bytes();key=ssl('pkeyutl','-decrypt','-inkey',priv,'-in',WORK/'wrapped.bin','-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256','-pkeyopt','rsa_mgf1_md:sha256',binary=True,log=False)
  eq(AESGCM(key).decrypt(b[394:406],b[414:],b[:414]),plain.read_bytes())
  key=secrets.token_bytes(32);nonce=secrets.token_bytes(12);secret=WORK/'aes-secret.bin';secret.write_bytes(key)
  wrapped=ssl('pkeyutl','-encrypt','-pubin','-inkey',pub,'-in',secret,'-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256','-pkeyopt','rsa_mgf1_md:sha256',binary=True,log=False);secret.unlink()
  h=b'L2PK\x01\x01\0\0'+len(wrapped).to_bytes(2,'big')+wrapped+nonce+len(plain.read_bytes()).to_bytes(8,'big');pkg=WORK/'reference.l2pk';pkg.write_bytes(h+AESGCM(key).encrypt(nonce,plain.read_bytes(),h));out=WORK/'reference.txt';cli('decrypt','--priv',priv,'--in',pkg,'--out',out);eq(out.read_bytes(),plain.read_bytes())
 (WORK/'wrapped.bin').write_bytes(dpack.read_bytes()[10:394]) if dpack.exists() else None
 group('D-INTEROP-REFERENCE',d_reference)
 # D-T11 is evidence from the student's previous two-group exchange; not faked as automated.
 records.append(dict(id='D-T11',status='SKIPPED-USER-REQUEST',checks=0,seconds=0,reason='Original report contains the Ha/Thang exchange screenshots. Revalidation intentionally omitted at the user request.'))
 # Built-in selftest reports every E group and does not print secrets.
 eout=''
 def eself():
  global eout
  eout=cli('kem-selftest','--pub',pub,'--priv',priv,contains='9/9 PASS');assert 'FAIL' not in eout
 group('E-SELFTEST',eself)
 for i in range(1,5):group('E-T'+str(i),lambda i=i:eq(bool(re.search(r'E-T'+str(i)+r'.*PASS',eout)),True))
 group('E-T5',lambda:[roundtrip('kem-encrypt','kem-decrypt',k/('public.'+a),k/('private.'+b),plain,'e-matrix-'+a+b) for a,b in itertools.product(['pem','der'],repeat=2)])
 epack=WORK/'base-e.l2pk';cli('kem-encrypt','--pub',pub,'--in',plain,'--out',epack)
 def e6():
  b=epack.read_bytes()
  for name,data in [('klen',b[:8]+(385).to_bytes(2,'big')+b[10:]),('range',b[:10]+b'\xff'*384+b[394:]),('zero',b[:10]+b'\0'*384+b[394:])]:
   p=WORK/('e-'+name);p.write_bytes(data);negative('kem-decrypt',priv,p,3,'e6-'+name)
 group('E-T6',e6)
 group('E-T7',lambda:negative('kem-decrypt',priv,mutated(epack,'e7',393),4,'e7'))
 group('E-T8',lambda:[negative('kem-decrypt',priv,mutated(epack,'e8-'+str(off),off),4,'e8-'+str(off)) for off in [394,426,446,-1]])
 def e9():
  negative('kem-decrypt',wrong/'private.pem',epack,4,'e9-wrong');negative('kem-decrypt',priv,dpack,3,'e9-mode');negative('kem-decrypt',priv,mutated(epack,'e9-version',4,value=2),3,'e9-version')
 group('E-T9',e9)
 def output_safety():
  existing=WORK/'protected.txt';existing.write_bytes(b'KEEP')
  cli('decrypt','--priv',priv,'--in',dpack,'--out',existing,code=2);eq(existing.read_bytes(),b'KEEP')
  bad=mutated(dpack,'force-bad',-1);cli('decrypt','--priv',priv,'--in',bad,'--out',existing,'--force',code=4);eq(existing.read_bytes(),b'KEEP');eq(Path(str(existing)+'.part').exists(),False)
  cli('decrypt','--priv',priv,'--in',dpack,'--out',dpack,'--force',code=1)
 group('EXTRA-output-safety',output_safety)
 def arithmetic_properties():
  import math,random
  rng=random.Random(25521679)  # Test reproducibility only, never cryptographic randomness.
  for _ in range(18):
   a=rng.getrandbits(260);b=rng.getrandbits(190);m=rng.getrandbits(210)|1
   for op,expect in [('mod-add',(a+b)%m),('mod-sub',(a-b)%m),('mod-mul',(a*b)%m),('mod-exp',pow(a,b,m)),('gcd',math.gcd(a,b))]:
    nums=[a,b] if op=='gcd' else [a,b,m];eq(cli(op,*map(str,nums)),str(expect))
   if math.gcd(a,m)==1:eq(cli('mod-inverse',str(a),str(m)),str(pow(a,-1,m)))
 group('EXTRA-independent-bigint-properties',arithmetic_properties)
 def parser_regressions():
  for enc,dec,basepack in [('encrypt','decrypt',dpack),('kem-encrypt','kem-decrypt',epack)]:
   b=basepack.read_bytes()
   for length in [0,1,4,8,9,10,30,len(b)-17,len(b)-1]:
    p=WORK/(dec+'-cut-'+str(length));p.write_bytes(b[:length]);negative(dec,priv,p,3,dec+'-cut-'+str(length))
   for badkey in [WORK/'weak.pem',WORK/'pkcs1.der',priv]:
    cli(enc,'--pub',badkey,'--in',plain,'--out',WORK/(enc+'-bad-key'),code=3)
   cli(enc,'--pub',pub,'--in',WORK/'absent','--out',WORK/'never',code=2)
  for c in [('key-info','--pub',str(pub),'--extra','x'),('key-info','--pub',str(pub),'--pub',str(pub)),('keygen','--bits'),('raw-rsa','--bits','2048'),('os2ip','--hex','0'),('os2ip','--hex','zz'),('i2osp','--int','1','--len','0')]:cli(*c,code=1)
 group('EXTRA-parser-regressions',parser_regressions)

finally:
 report=dict(executable=str(EXE),time_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),checks=checks,results=records,excluded_by_user=['D-T11 external fixture replay'])
 (LOG/'summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8');(LOG/'run_all.log').write_text('\n\n'.join(details),encoding='utf8')
 if not args.keep_work:
  assert WORK.resolve().is_relative_to((ROOT/'tests').resolve())
  shutil.rmtree(WORK)
failed=[r for r in records if r['status']=='FAIL'];print(f'{checks} assertions; {len(failed)} failed groups; D-T11 revalidation omitted by request; original manual evidence retained.')
sys.exit(1 if failed else 0)
