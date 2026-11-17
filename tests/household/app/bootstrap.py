"""Reconcile synthetic YAML users into this demo's LLDAP, never production."""
import json
import sys
import time
import requests
import yaml
from ldap3 import Server, Connection

BASE='http://lldap:17170'
ADMIN='LocalDemo-admin-12345'

def login():
 response=requests.post(BASE+'/auth/simple/login',json={'username':'admin','password':ADMIN},timeout=10)
 response.raise_for_status();return response.json()['token']

def graphql(query, variables=None):
 response=requests.post(BASE+'/api/graphql',headers={'Authorization':'Bearer '+login()},json={'query':query,'variables':variables or {}},timeout=10)
 response.raise_for_status();data=response.json()
 if data.get('errors'): raise RuntimeError(data['errors'])
 return data['data']

def update(user, attributes):
 return graphql('mutation($user:UpdateUserInput!){updateUser(user:$user){ok}}',{'user':{'id':user,'insertAttributes':attributes}})

def reconcile(path):
 cfg=yaml.safe_load(open(path))
 schema=graphql('{schema{userSchema{attributes{name}}}}')
 existing={x['name'] for x in schema['schema']['userSchema']['attributes']}
 for name,is_list in [('auth-person-id',False),('auth-identities',True)]:
  if name not in existing:
   graphql('mutation($name:String!,$list:Boolean!){addUserAttribute(name:$name,attributeType:STRING,isList:$list,isVisible:true,isEditable:false){ok}}',{'name':name,'list':is_list})
 current=graphql('{groups{id displayName}}')['groups'];groups={g['displayName']:g['id'] for g in current}
 for name in cfg['groups']:
  if name not in groups:groups[name]=graphql('mutation($name:String!){createGroup(name:$name){id}}',{'name':name})['createGroup']['id']
 current_users=graphql('{users{id attributes{name value}}}')['users']
 existing={u['id'] for u in current_users}
 desired_users={u['id'] for u in cfg['users']}
 for user in current_users:
  managed=any(a['name']=='auth-person-id' and a['value'] for a in user['attributes'])
  if managed and user['id'] not in desired_users:
   graphql('mutation($id:String!){deleteUser(userId:$id){ok}}',{'id':user['id']})
 for u in cfg['users']:
  attrs=[{'name':'auth-person-id','value':[u['personId']]},{'name':'auth-identities','value':[json.dumps(x,separators=(',',':')) for x in u['identities']]}]
  if u['id'] not in existing:
   graphql('mutation($user:CreateUserInput!){createUser(user:$user){id}}',{'user':{'id':u['id'],'email':u['email'],'displayName':u['displayName'],'attributes':attrs}})
  else:
   graphql('mutation($user:UpdateUserInput!){updateUser(user:$user){ok}}',{'user':{'id':u['id'],'email':u['email'],'displayName':u['displayName'],'insertAttributes':attrs}})
  membership=graphql('query($id:String!){user(userId:$id){groups{id displayName}}}',{'id':u['id']})['user']['groups']
  actual={g['displayName'] for g in membership};desired=set(u['groups'])
  for name in actual-desired:
   graphql('mutation($uid:String!,$gid:Int!){removeUserFromGroup(userId:$uid,groupId:$gid){ok}}',{'uid':u['id'],'gid':groups[name]})
  for name in desired-actual:
   graphql('mutation($uid:String!,$gid:Int!){addUserToGroup(userId:$uid,groupId:$gid){ok}}',{'uid':u['id'],'gid':groups[name]})
  conn=Connection(Server('lldap',port=3890),'uid=admin,ou=people,dc=household,dc=test',ADMIN,auto_bind=True)
  assert conn.extend.standard.modify_password('uid='+u['id']+',ou=people,dc=household,dc=test',None,'LocalDemo-'+u['id']+'-12345'),conn.result
  conn.unbind()
 print('Reconciled scratch LLDAP users, immutable person IDs, protected bindings and groups.')

if __name__=='__main__':reconcile(sys.argv[1])
