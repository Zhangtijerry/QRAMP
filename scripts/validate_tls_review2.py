#!/usr/bin/env python3
"""Bounded signed loopback TLS version agreement test; no external endpoints."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import warnings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import yaml
from qramp.collectors import tls
from qramp.model import Inventory

def run_profile(out,cipher):
 out=Path(out);out.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory() as td:
  td=Path(td);key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.now(timezone.utc)
  cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).sign(key,hashes.SHA256())
  (td/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));(td/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.maximum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(str(td/'cert.pem'),str(td/'key.pem'));ctx.set_ciphers(cipher)
  listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(5);listener.settimeout(0.2);port=listener.getsockname()[1];stop=threading.Event()
  def serve():
   while not stop.is_set():
    try:conn,_=listener.accept()
    except socket.timeout:continue
    except OSError:break
    conn.settimeout(2)
    try:
     with ctx.wrap_socket(conn,server_side=True) as s:s.sendall(b'local validation\n')
    except (ssl.SSLError,OSError):conn.close()
  thread=threading.Thread(target=serve,daemon=True);thread.start()
  try:
   scope=td/'scope.yaml';secret=td/'scope.key';secret.write_text('local-validation-only')
   scope.write_text(yaml.safe_dump({'version':1,'expires':(now+timedelta(hours=1)).isoformat(),'targets':[{'host':'127.0.0.1','port':port}]}))
   tls.sign_scope(str(scope),str(secret))
   inv=Inventory()
   with warnings.catch_warnings():
    warnings.simplefilter('ignore',DeprecationWarning);stats=tls.run(inv,scope_path=str(scope),scope_key=str(secret))
   observed={a.params for a in inv.assets if a.primitive=='protocol'}
   rows=[]
   for version,flag in [('1.0','-tls1'),('1.1','-tls1_1'),('1.2','-tls1_2'),('1.3','-tls1_3')]:
    command=['openssl','s_client','-connect',f'127.0.0.1:{port}',flag,'-cipher','ALL:@SECLEVEL=0','-brief']
    p=subprocess.run(command,input='',text=True,capture_output=True,timeout=5);log=p.stdout+p.stderr
    negotiated='Protocol version:' in log
    (out/f'openssl-tls-{version}.txt').write_text(log)
    rows.append({'version':version,'openssl_negotiated':negotiated,'qramp_observed':version in observed,'equal':negotiated==(version in observed),'returncode':p.returncode})
   result={'tls12_cipher_profile':cipher,'scope':'four forced protocol versions against one signed loopback service; not internet deployment, exact group detection, PQ handshake or decommission validation','python_ssl':ssl.OPENSSL_VERSION,'reference_openssl':subprocess.check_output(['openssl','version'],text=True).strip(),'rows':rows,'TP':sum(r['openssl_negotiated'] and r['qramp_observed'] for r in rows),'FP':sum(not r['openssl_negotiated'] and r['qramp_observed'] for r in rows),'FN':sum(r['openssl_negotiated'] and not r['qramp_observed'] for r in rows),'TN':sum(not r['openssl_negotiated'] and not r['qramp_observed'] for r in rows),'collector_stats':stats}
   (out/'tls-comparison.json').write_text(json.dumps(result,indent=2)+'\n');return result
  finally:stop.set();listener.close();thread.join(timeout=3)
def run(out):
 out=Path(out);out.mkdir(parents=True,exist_ok=True)
 profiles=[run_profile(out/name,cipher) for name,cipher in [('rsa-only','AES256-GCM-SHA384'),('ecdhe','ECDHE-RSA-AES256-GCM-SHA384')]]
 result={'scope':'two signed loopback suite profiles, four forced protocol versions each; profiles share a local service design and are not independent deployments','profiles':profiles,**{k:sum(x[k] for x in profiles) for k in ('TP','FP','FN','TN')}}
 (out/'tls-comparison.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(__doc__);p.add_argument('--out',default='review2-validation');print(json.dumps(run(p.parse_args().out),indent=2))
