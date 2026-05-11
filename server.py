import sys, sqlite3, hashlib, secrets, datetime, eventlet, os, base64, json, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit

eventlet.monkey_patch()

_=lambda s:hashlib.pbkdf2_hmac('sha256',s.encode(),os.urandom(16),100000)
__=lambda p,s:PBKDF2(algorithm=hashes.SHA256(),length=32,salt=s,iterations=300000).derive(p.encode())
___=lambda d:base64.b64encode(d).decode()
____=lambda d:base64.b64decode(d)

app=Flask(__name__)
app.config['SECRET_KEY']=secrets.token_hex(32)
socketio=SocketIO(app,cors_allowed_origins="*",async_mode='eventlet')

DB='zdb.db'
KF='kf.key'

def _a(p,s=None):
 if not s:s=os.urandom(32)
 k=PBKDF2(algorithm=hashes.SHA256(),length=32,salt=s,iterations=300000).derive(p.encode())
 return k,s

def _b():
 if os.path.exists(KF):
  with open(KF,'r') as f:
   d=json.load(f)
   return ____(d['k']),____(d['s'])
 else:
  p=secrets.token_urlsafe(32)
  k,s=_a(p)
  with open(KF,'w') as f:
   json.dump({'k':___(k),'s':___(s),'p':p},f)
  print(f"R: {p}")
  return k,s

MK,_=_b()

def _c(data):
 n=os.urandom(12)
 aes=AESGCM(MK)
 ct=aes.encrypt(n,data.encode(),None)
 return ___(n)+___(ct)

def _d(data):
 n=____(data[:16])
 ct=____(data[16:])
 aes=AESGCM(MK)
 return aes.decrypt(n,ct,None).decode()

def _e():
 c=sqlite3.connect(DB);c.execute('''CREATE TABLE IF NOT EXISTS u(i INTEGER PRIMARY KEY AUTOINCREMENT,u TEXT UNIQUE NOT NULL,p TEXT NOT NULL,s TEXT NOT NULL,k TEXT NOT NULL,ct TEXT NOT NULL)''')
 c.execute('''CREATE TABLE IF NOT EXISTS m(i INTEGER PRIMARY KEY AUTOINCREMENT,fu TEXT NOT NULL,tu TEXT NOT NULL,em TEXT NOT NULL,ts TEXT NOT NULL,dv INTEGER DEFAULT 0)''')
 c.commit();c.close()
 print("DB OK")

_e()

U={}

def _f(p,s=None):
 if not s:s=secrets.token_hex(16)
 return hashlib.pbkdf2_hmac('sha256',p.encode(),s.encode(),100000).hex(),s

@app.route('/g', methods=['POST'])
def _g():
 d=request.json;u=d.get('u','').strip();p=d.get('p','').strip();pk=d.get('k','')
 if not u or not p:return jsonify({'e':'F'}),400
 if len(u)<3:return jsonify({'e':'US'}),400
 if len(p)<6:return jsonify({'e':'PS'}),400
 c=sqlite3.connect(DB);cur=c.cursor()
 cur.execute("SELECT i FROM u WHERE u=?",(u,))
 if cur.fetchone():c.close();return jsonify({'e':'EX'}),400
 ph,s=_f(p)
 cur.execute("INSERT INTO u (u,p,s,k,ct) VALUES (?,?,?,?,?)",(u,ph,s,pk,_c(p)))
 c.commit();c.close()
 return jsonify({'s':'ok'})

@app.route('/h', methods=['POST'])
def _h():
 d=request.json;u=d.get('u','').strip();p=d.get('p','').strip()
 c=sqlite3.connect(DB);cur=c.cursor()
 cur.execute("SELECT p,s,k FROM u WHERE u=?",(u,))
 r=cur.fetchone()
 if not r:c.close();return jsonify({'e':'NF'}),400
 sh,s,pk=r
 if _f(p,s)[0]!=sh:c.close();return jsonify({'e':'WP'}),400
 try:_d(pk)
 except:return jsonify({'e':'E'}),400
 c.close()
 return jsonify({'s':'ok','k':pk,'u':u})

@app.route('/k/<u>', methods=['GET'])
def _i(u):
 c=sqlite3.connect(DB);cur=c.cursor()
 cur.execute("SELECT k FROM u WHERE u=?",(u,))
 r=cur.fetchone()
 c.close()
 if r:return jsonify({'k':r[0]})
 return jsonify({'e':'NF'}),404

@app.route('/l', methods=['GET'])
def _j():
 c=sqlite3.connect(DB);cur=c.cursor()
 cur.execute("SELECT u FROM u")
 us=[r[0] for r in cur.fetchall()]
 c.close()
 return jsonify({'u':us})

@socketio.on('cn')
def _k(d):
 u=d.get('u')
 if u:U[u]=request.sid;emit('on',{'u':u},broadcast=True);emit('ls',{'u':list(U.keys())})

@socketio.on('dc')
def _l():
 for u,s in list(U.items()):
  if s==request.sid:del U[u];emit('off',{'u':u},broadcast=True);break

@socketio.on('sm')
def _m(d):
 fu=d.get('f');tu=d.get('t');em=d.get('e');ts=datetime.datetime.now().isoformat()
 c=sqlite3.connect(DB);cur=c.cursor()
 cur.execute("INSERT INTO m (fu,tu,em,ts) VALUES (?,?,?,?)",(fu,tu,em,ts))
 c.commit();c.close()
 if tu in U:emit('nm',{'f':fu,'e':em,'ts':ts},room=U[tu])
 emit('ms',{'s':'ok','t':tu})

@socketio.on('gom')
def _n(d):
 u=d.get('u')
 c=sqlite3.connect(DB);cur=c.cursor()
 cur.execute("SELECT fu,em,ts FROM m WHERE tu=? AND dv=0",(u,))
 ms=cur.fetchall()
 if ms:
  cur.execute("UPDATE m SET dv=1 WHERE tu=?",(u,))
  c.commit()
  emit('om',{'m':[{'f':m[0],'e':m[1],'ts':m[2]} for m in ms]})
 c.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)