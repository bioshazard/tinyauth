"""HTTP/OIDC integration checks; synthetic scratch services only."""
import base64
import hashlib
import json
import secrets
import sys
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import requests
import urllib3
from bootstrap import graphql, update, reconcile
from server import ISSUER, CALLBACK, CLIENT_SECRETS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
RESULTS=[]
def check(label, condition):
 assert condition,label
 RESULTS.append(label); print('PASS',label,flush=True)

def call(session, method, url, **kw):
 url=url.replace('http://localhost:28080','http://demo:8080')
 return session.request(method,url,allow_redirects=False,verify=False,timeout=15,**kw)

def login(kind='ldap',persona='wife',provider='demo-google'):
 s=requests.Session()
 if kind=='ldap':
  r=call(s,'POST',ISSUER+'/api/user/login',json={'username':persona,'password':'LocalDemo-'+persona+'-12345'})
  assert r.status_code==200,(r.status_code,r.text)
 else:
  r=call(s,'GET',ISSUER+'/api/oauth/url/'+provider)
  assert r.status_code==200,r.text
  r=call(s,'GET',r.json()['url']+'&persona='+persona)
  assert r.status_code==302,(r.status_code,r.text)
  r=call(s,'GET',r.headers['Location'])
  assert r.status_code in [302,307],(r.status_code,r.text)
  assert '/error' not in r.headers['Location'],r.headers['Location']
 return s

def authorize(s,client='immich-demo',redirect=CALLBACK):
 verifier=secrets.token_urlsafe(48);nonce=secrets.token_urlsafe(24);state=secrets.token_urlsafe(24)
 challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
 r=call(s,'GET',ISSUER+'/authorize',params={'response_type':'code','client_id':client,'redirect_uri':redirect,'scope':'openid email profile groups','nonce':nonce,'state':state,'code_challenge':challenge,'code_challenge_method':'S256'})
 assert r.status_code==302,(r.status_code,r.text)
 q=parse_qs(urlparse(r.headers['Location']).query)
 if 'oidc_ticket' not in q:return r,None
 r=call(s,'POST',ISSUER+'/api/oidc/authorize-complete',json={'ticket':q['oidc_ticket'][0]})
 if r.status_code!=200:return r,None
 q=parse_qs(urlparse(r.json()['redirect_uri']).query)
 assert q.get('state')==[state],q
 return r,{'code':q['code'][0],'verifier':verifier,'nonce':nonce,'client':client,'redirect':redirect}

def exchange(s,a,verifier=None):
 return call(s,'POST',ISSUER+'/api/oidc/token',data={'grant_type':'authorization_code','client_id':a['client'],'client_secret':CLIENT_SECRETS[a['client']],'code':a['code'],'redirect_uri':a['redirect'],'code_verifier':a['verifier'] if verifier is None else verifier})

def mint(s,client='immich-demo'):
 r,a=authorize(s,client);assert a,(r.status_code,r.text)
 r=exchange(s,a);assert r.status_code==200,(r.status_code,r.text)
 t=r.json();jwk=call(s,'GET',ISSUER+'/.well-known/jwks.json').json()['keys'][0]
 claims=jwt.decode(t['id_token'],jwt.PyJWK.from_dict(jwk).key,algorithms=['RS256'],issuer=ISSUER,audience=client)
 assert claims['nonce']==a['nonce'];assert '_household' not in claims
 return t,claims,a

def refresh(t):
 return call(requests.Session(),'POST',ISSUER+'/api/oidc/token',data={'grant_type':'refresh_token','client_id':'immich-demo','client_secret':CLIENT_SECRETS['immich-demo'],'refresh_token':t['refresh_token']})

def userinfo(t):return call(requests.Session(),'GET',ISSUER+'/api/oidc/userinfo',headers={'Authorization':'Bearer '+t['access_token']})

def proxy(s,host='whoami.localtest.me'):
 return requests.get('http://tinyauth:3000/api/auth/traefik',headers={'Cookie':'; '.join(k+'='+v for k,v in s.cookies.get_dict().items()),'X-Forwarded-Host':host,'X-Forwarded-Proto':'https','X-Forwarded-Uri':'/','X-Forwarded-Method':'GET','Remote-User':'forged','Remote-Sub':'forged','Accept':'application/json'},timeout=15)

def run():
 ldap=login();lt,lc,_=mint(ldap)
 google=login('oauth');gt,gc,_=mint(google)
 check('Google and LDAP issue identical signed (issuer, subject)',(lc['iss'],lc['sub'])==(gc['iss'],gc['sub']))
 check('Both methods use directory-owned username, email, name and groups',all(lc[k]==gc[k] for k in ['preferred_username','email','name','groups']) and gc['preferred_username']=='wife' and gc['email']=='wife@household.test' and 'household' in gc['groups'])
 check('Internal binding metadata is absent from public userinfo','_household' not in userinfo(gt).json())
 lp=proxy(ldap);gp=proxy(google)
 assert lp.status_code==gp.status_code==200,(lp.status_code,lp.text,gp.status_code,gp.text)
 check('ForwardAuth accepts both login methods',True)
 check('ForwardAuth emits the same canonical identity and groups',all(lp.headers.get(k)==gp.headers.get(k) for k in ['Remote-User','Remote-Email','Remote-Groups','Remote-Sub']) and gp.headers.get('Remote-User')=='wife' and gp.headers.get('Remote-Sub')=='724045e4-90b1-4abd-b2d4-9c0e605081c5')
 check('ForwardAuth denies a missing directory group',proxy(google,'denied.localtest.me').status_code==403)
 check('ForwardAuth denies an unlisted hostname',proxy(google,'unknown.localtest.me').status_code==403)
 check('Spoofed identity headers cannot authenticate',proxy(requests.Session()).status_code==401)

 r,_=authorize(login('oauth',persona='attacker'));check('Same username/email from an unbound subject is denied',r.status_code==403)
 r,_=authorize(login('oauth',provider='demo-other'));check('Same subject from a different provider is denied',r.status_code==403)
 r,_=authorize(google,'admin-demo');check('Directory group denies unauthorized OIDC client',r.status_code==403)
 r,_=authorize(login(persona='other'));check('Different directory person does not inherit household access',r.status_code==403)
 # Username/email are mutable labels; the explicit person identifier is stable.
 graphql('mutation{updateUser(user:{id:"wife",email:"changed@household.test",displayName:"Changed Name"}){ok}}')
 try:
  _,changed,_=mint(google);check('Email/display-name change preserves subject',changed['sub']==gc['sub'] and changed['email']=='changed@household.test')
 finally:graphql('mutation{updateUser(user:{id:"wife",email:"wife@household.test",displayName:"Demo Wife"}){ok}}')
 # Username/binding reassignment cannot turn old authenticated sessions into a new person.
 pinned_ldap=login();pinned_google=login('oauth');old_token,_,_=mint(pinned_google)
 original='724045e4-90b1-4abd-b2d4-9c0e605081c5'
 update('wife',[{'name':'auth-person-id','value':['e0b43d97-61d5-424e-b5d7-11bc6be14dd8']}])
 try:
  r,_=authorize(pinned_ldap);check('Recycled LDAP username cannot transfer an old SSO session',r.status_code==403)
  r,_=authorize(pinned_google);check('Reassigned Google binding cannot transfer an old SSO session',r.status_code==403)
  check('Reassigned person ID cannot transfer an existing refresh token',refresh(old_token).status_code!=200)
  _,fresh,_=mint(login('oauth'));check('Fresh authentication sees the deliberately reassigned person',fresh['sub']!=gc['sub'])
 finally:update('wife',[{'name':'auth-person-id','value':[original]}])
 # A binding must identify exactly one directory person.
 binding='["https://accounts.google.com","google-wife-001"]'
 update('other',[{'name':'auth-identities','value':[binding]}])
 try:r,_=authorize(google);check('Ambiguous duplicate external binding fails closed',r.status_code==403)
 finally:update('other',[{'name':'auth-identities','value':[]}])
 # Removing the binding revokes both a live SSO cookie's OIDC grant and refresh/userinfo.
 gt,_,_=mint(google)
 update('wife',[{'name':'auth-identities','value':[]}])
 try:
  r,_=authorize(google);check('Removed binding blocks an existing SSO session',r.status_code==403)
  check('Removed binding blocks ForwardAuth',proxy(google).status_code==403)
  check('Removed binding blocks existing refresh token',refresh(gt).status_code!=200)
  check('Removed binding blocks existing access-token userinfo',userinfo(gt).status_code==401)
 finally:update('wife',[{'name':'auth-identities','value':[binding]}])
 gt,_,_=mint(google)
 gid=next(g['id'] for g in graphql('{groups{id displayName}}')['groups'] if g['displayName']=='household')
 graphql('mutation($gid:Int!){removeUserFromGroup(userId:"wife",groupId:$gid){ok}}',{'gid':gid})
 try:
  r,_=authorize(google);check('Removed group blocks a new authorization',r.status_code==403)
  check('Removed group blocks existing refresh token',refresh(gt).status_code!=200)
 finally:graphql('mutation($gid:Int!){addUserToGroup(userId:"wife",groupId:$gid){ok}}',{'gid':gid})
 # Check authoritative YAML removal, then rebuild the same logical person.
 import tempfile,yaml
 cfg=yaml.safe_load(open('/demo/directory.yaml'))
 removed=dict(cfg,users=[u for u in cfg['users'] if u['id']!='wife'])
 with tempfile.NamedTemporaryFile(mode='w',suffix='.yaml') as f:
  yaml.safe_dump(removed,f);f.flush()
  try:
   reconcile(f.name)
   r,_=authorize(google);check('Removing person from YAML removes access through existing SSO',r.status_code==403)
  finally:reconcile('/demo/directory.yaml')
 _,rebuilt,_=mint(login('oauth'))
 check('Rebuilding LLDAP user from YAML preserves OIDC subject',rebuilt['sub']==gc['sub'])
 # Protect binding attributes against end-user account reassignment.
 token=requests.post('http://lldap:17170/auth/simple/login',json={'username':'wife','password':'LocalDemo-wife-12345'},timeout=10).json()['token']
 r=requests.post('http://lldap:17170/api/graphql',headers={'Authorization':'Bearer '+token},json={'query':'mutation{updateUser(user:{id:"wife",insertAttributes:[{name:"auth-identities",value:["evil"]}]}){ok}}'},timeout=10)
 check('Ordinary LDAP user cannot edit identity-binding attributes',bool(r.json().get('errors')))
 # Protocol boundary checks on the actual code/token endpoints.
 r,a=authorize(google);r=exchange(google,a,'incorrect-verifier');check('Wrong PKCE verifier is rejected',r.status_code==400)
 t,_,a=mint(google);r=exchange(google,a);check('Authorization code reuse is rejected',r.status_code==400)
 r=call(google,'GET',ISSUER+'/authorize',params={'response_type':'code','client_id':'immich-demo','redirect_uri':'https://evil.invalid/callback','scope':'openid'})
 check('Unregistered redirect never receives a code','evil.invalid' not in r.headers.get('Location',''))
 # The demo relying party separately verifies JWT signature, audience, issuer, nonce and state.
 rp=requests.Session();r=call(rp,'GET','http://localhost:28080/login');r=call(google,'GET',r.headers['Location']);ticket=parse_qs(urlparse(r.headers['Location']).query)['oidc_ticket'][0]
 r=call(google,'POST',ISSUER+'/api/oidc/authorize-complete',json={'ticket':ticket});r=call(rp,'GET',r.json()['redirect_uri'])
 check('Test OIDC app completes callback and verifies signed token',r.status_code==200 and r.json()['verified'])
 # Leave a live token so the host can restart only Tinyauth, then run after_restart.
 t,c,_=mint(google)
 open('/tmp/household-restart.json','w').write(json.dumps({'token':t,'subject':c['sub']}))
 print(json.dumps({'checks':RESULTS,'subject':gc['sub']},indent=2))

def after_restart():
 old=json.load(open('/tmp/household-restart.json'))
 check('Memory-only restart invalidates old refresh token',refresh(old['token']).status_code!=200)
 check('Memory-only restart invalidates old access-token userinfo',userinfo(old['token']).status_code==401)
 _,ldap,_=mint(login());t,google,_=mint(login('oauth'))
 check('Restart preserves canonical subject for both methods',ldap['sub']==google['sub']==old['subject'])
 open('/tmp/household-outage.json','w').write(json.dumps(t))
 print('All restart invariants passed.')

def outage():
 t=json.load(open('/tmp/household-outage.json'))
 r,_=authorize(login('oauth'));check('Directory outage denies new authorization',r.status_code==403)
 check('Directory outage denies refresh',refresh(t).status_code!=200)
 check('Directory outage denies userinfo',userinfo(t).status_code==401)

if __name__=='__main__':
 {'run':run,'after-restart':after_restart,'outage':outage}[sys.argv[1] if len(sys.argv)>1 else 'run']()
