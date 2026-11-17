"""LOCAL DEMO ONLY: fake upstream OAuth, real OIDC relying party, and TLS proxy.
The mock provider has no real authentication. Never point a real service at it.
"""
import base64
import hashlib
import html
import json
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import requests

ISSUER = 'https://auth.localtest.me:28443'
CALLBACK = 'http://localhost:28080/callback'
CODES, TOKENS, PENDING = {}, {}, {}
PERSONAS = {
 'wife': {'sub':'google-wife-001','email':'wife.personal@gmail.example','name':'Google Display Name','preferred_username':'google-alias'},
 'attacker': {'sub':'attacker-002','email':'wife@household.test','name':'Lookalike','preferred_username':'wife'},
}
CLIENT_SECRETS = {'immich-demo':'local-demo-oidc-secret','admin-demo':'local-demo-admin-client-secret'}

class Handler(BaseHTTPRequestHandler):
 def log_message(self, *args): pass
 def send(self, status, body, content='application/json', headers=None):
  raw = body.encode() if isinstance(body,str) else json.dumps(body).encode()
  self.send_response(status)
  self.send_header('Content-Type', content)
  self.send_header('Cache-Control','no-store')
  for k,v in (headers or {}).items(): self.send_header(k,v)
  self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
 def redirect(self, location): self.send(302,'',headers={'Location':location})
 def do_POST(self):
  body=self.rfile.read(int(self.headers.get('Content-Length',0)))
  if self.server.server_port==28443: return self.proxy(body)
  if self.path=='/mock/token':
   form=parse_qs(body.decode()); code=form.get('code',[''])[0]
   record=CODES.pop(code,None)
   if not record: return self.send(400,{'error':'invalid_grant'})
   if record['challenge']:
    actual=base64.urlsafe_b64encode(hashlib.sha256(form.get('code_verifier',[''])[0].encode()).digest()).rstrip(b'=').decode()
    if actual!=record['challenge']:return self.send(400,{'error':'invalid_grant'})
   token=secrets.token_urlsafe(32);TOKENS[token]=record['claims']
   return self.send(200,{'access_token':token,'token_type':'Bearer','expires_in':300})
  return self.send(404,{})
 def do_GET(self):
  if self.server.server_port==28443:return self.proxy()
  u=urlparse(self.path);q=parse_qs(u.query)
  if u.path=='/mock/authorize':
   choice=q.get('persona',[''])[0]
   if not choice:
    links=[]
    for name in PERSONAS:
     query={k:v[0] for k,v in q.items()};query['persona']=name
     links.append(f'<p><a href="?{html.escape(urlencode(query))}">{name}</a></p>')
    return self.send(200,'<h1>Mock Google: choose a synthetic identity</h1>'+''.join(links),'text/html')
   claims=PERSONAS.get(choice)
   if not claims:return self.send(400,{'error':'unknown_persona'})
   code=secrets.token_urlsafe(32)
   CODES[code]={'claims':claims,'challenge':q.get('code_challenge',[''])[0]}
   return self.redirect(q['redirect_uri'][0]+'?'+urlencode({'code':code,'state':q['state'][0]}))
  if u.path=='/mock/userinfo':
   claims=TOKENS.get(self.headers.get('Authorization','').removeprefix('Bearer '))
   return self.send(200 if claims else 401,dict(claims or {},email_verified=True))
  if u.path=='/login':
   client=q.get('client',['immich-demo'])[0]; state=secrets.token_urlsafe(24);nonce=secrets.token_urlsafe(24);verifier=secrets.token_urlsafe(48)
   PENDING[state]={'client':client,'nonce':nonce,'verifier':verifier}
   challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
   return self.redirect(ISSUER+'/authorize?'+urlencode({'client_id':client,'redirect_uri':CALLBACK,'response_type':'code','scope':'openid email profile groups','state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'}))
  if u.path=='/callback':
   pending=PENDING.pop(q.get('state',[''])[0],None)
   if not pending:return self.send(400,{'error':'invalid_state'})
   if 'error' in q:return self.send(403,{'error':q['error'][0]})
   token=requests.post('http://tinyauth:3000/api/oidc/token',data={'grant_type':'authorization_code','client_id':pending['client'],'client_secret':CLIENT_SECRETS[pending['client']],'redirect_uri':CALLBACK,'code':q['code'][0],'code_verifier':pending['verifier']},timeout=10)
   if token.status_code!=200:return self.send(400,{'error':'token_exchange_failed','details':token.json()})
   data=token.json();jwk=requests.get('http://tinyauth:3000/.well-known/jwks.json',timeout=10).json()['keys'][0]
   claims=jwt.decode(data['id_token'],jwt.PyJWK.from_dict(jwk).key,algorithms=['RS256'],audience=pending['client'],issuer=ISSUER)
   if claims.get('nonce')!=pending['nonce']:return self.send(400,{'error':'nonce_mismatch'})
   return self.send(200,{'verified':True,'claims':claims})
  if u.path=='/health':return self.send(200,{'ok':True})
  return self.send(200,'<h1>Household identity prototype</h1><p>Real LLDAP + patched Tinyauth; fake Google; test OIDC app.</p><p><a href="/login">Sign into test app</a></p><p><a href="/login?client=admin-demo">Admin app (wife should be denied)</a></p><p>LDAP user: wife / LocalDemo-wife-12345</p><p>OAuth: choose Mock Google, then wife. Upstream username/email deliberately differ from LDAP.</p>','text/html')
 def proxy(self, body=None):
  headers={k:v for k,v in self.headers.items() if k.lower() not in ['host','content-length','connection']}
  headers.update({'X-Forwarded-Proto':'https','X-Forwarded-Host':'auth.localtest.me:28443'})
  try:r=requests.request(self.command,'http://tinyauth:3000'+self.path,headers=headers,data=body,allow_redirects=False,timeout=15)
  except requests.RequestException:return self.send(502,{'error':'tinyauth_not_ready'})
  self.send_response(r.status_code)
  for k,v in r.headers.items():
   if k.lower() not in ['transfer-encoding','content-length','content-encoding','connection','set-cookie']:self.send_header(k,v)
  for cookie in r.raw.headers.getlist('Set-Cookie'): self.send_header('Set-Cookie',cookie)
  self.send_header('Content-Length',str(len(r.content)));self.end_headers();self.wfile.write(r.content)

if __name__=='__main__':
 plain=ThreadingHTTPServer(('0.0.0.0',8080),Handler)
 tls=ThreadingHTTPServer(('0.0.0.0',28443),Handler)
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain('/tls/cert.pem','/tls/key.pem');tls.socket=ctx.wrap_socket(tls.socket,server_side=True)
 threading.Thread(target=plain.serve_forever,daemon=True).start();tls.serve_forever()
