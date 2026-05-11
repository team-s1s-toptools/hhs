import sys, sqlite3, hashlib, secrets, datetime, os, base64, json, hmac, threading
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

DB = "zet.db"
KF = "kf.key"

# ========== КРИПТО ФУНКЦИИ (без внешних библиотек) ==========
def _derive_key(pwd: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, 300000)
    return key, salt

def _init_master():
    if os.path.exists(KF):
        with open(KF, 'r') as f:
            d = json.load(f)
        return base64.b64decode(d['k']), base64.b64decode(d['s'])
    else:
        mp = secrets.token_urlsafe(32)
        k, s = _derive_key(mp)
        with open(KF, 'w') as f:
            json.dump({'k': base64.b64encode(k).decode(), 's': base64.b64encode(s).decode(), 'm': mp}, f)
        print(f"🔑 MASTER KEY (SAVE IT): {mp}")
        return k, s

MK, _ = _init_master()

def _enc(data: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(MK), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ct).decode()

def _dec(data: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    raw = base64.b64decode(data)
    iv = raw[:16]
    tag = raw[16:32]
    ct = raw[32:]
    cipher = Cipher(algorithms.AES(MK), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# ========== БАЗА ДАННЫХ ==========
def _init_db():
    c = sqlite3.connect(DB)
    c.execute('''CREATE TABLE IF NOT EXISTS u(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        u TEXT UNIQUE, ph TEXT, s TEXT, pk TEXT, ud TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS m(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fu TEXT, tu TEXT, em TEXT, ts TEXT, d INT DEFAULT 0)''')
    c.commit(); c.close()
    print("DB ready")

_init_db()

# ========== ВСПОМОГАТЕЛЬНЫЕ ==========
def _hash_pw(pwd: str, salt: str = None):
    if not salt:
        salt = secrets.token_hex(16)
    return hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt.encode(), 100000).hex(), salt

U = {}

# ========== HTTP ENDPOINTS ==========
@app.route('/reg', methods=['POST'])
def _reg():
    d = request.json
    u = d.get('u', '').strip()
    p = d.get('p', '').strip()
    pk = d.get('k', '')
    if not u or not p:
        return jsonify({'e': 'F'}), 400
    if len(u) < 3:
        return jsonify({'e': 'US'}), 400
    if len(p) < 6:
        return jsonify({'e': 'PS'}), 400
    c = sqlite3.connect(DB)
    cur = c.cursor()
    cur.execute("SELECT id FROM u WHERE u=?", (u,))
    if cur.fetchone():
        c.close()
        return jsonify({'e': 'EX'}), 400
    ph, s = _hash_pw(p)
    cur.execute("INSERT INTO u (u,ph,s,pk,ud) VALUES (?,?,?,?,?)", (u, ph, s, pk, _enc(p)))
    c.commit()
    c.close()
    return jsonify({'s': 'ok'})

@app.route('/log', methods=['POST'])
def _log():
    d = request.json
    u = d.get('u', '').strip()
    p = d.get('p', '').strip()
    c = sqlite3.connect(DB)
    cur = c.cursor()
    cur.execute("SELECT ph,s,pk FROM u WHERE u=?", (u,))
    r = cur.fetchone()
    if not r:
        c.close()
        return jsonify({'e': 'NF'}), 400
    sh, s, pk = r
    if _hash_pw(p, s)[0] != sh:
        c.close()
        return jsonify({'e': 'WP'}), 400
    c.close()
    return jsonify({'s': 'ok', 'k': pk, 'u': u})

@app.route('/key/<u>', methods=['GET'])
def _key(u):
    c = sqlite3.connect(DB)
    cur = c.cursor()
    cur.execute("SELECT pk FROM u WHERE u=?", (u,))
    r = cur.fetchone()
    c.close()
    if r:
        return jsonify({'k': r[0]})
    return jsonify({'e': 'NF'}), 404

# ========== WEBSOCKET ==========
@socketio.on('cn')
def _cn(d):
    u = d.get('u')
    if u:
        U[u] = request.sid
        emit('ol', {'u': list(U.keys())}, broadcast=True)

@socketio.on('dc')
def _dc():
    for u, sid in list(U.items()):
        if sid == request.sid:
            del U[u]
            emit('uf', {'u': u}, broadcast=True)
            break

@socketio.on('sm')
def _sm(d):
    fu = d.get('f')
    tu = d.get('t')
    em = d.get('e')
    ts = datetime.datetime.now().isoformat()
    c = sqlite3.connect(DB)
    cur = c.cursor()
    cur.execute("INSERT INTO m (fu,tu,em,ts) VALUES (?,?,?,?)", (fu, tu, em, ts))
    c.commit()
    c.close()
    if tu in U:
        emit('nm', {'f': fu, 'e': em, 'ts': ts}, room=U[tu])

@socketio.on('gom')
def _gom(d):
    u = d.get('u')
    c = sqlite3.connect(DB)
    cur = c.cursor()
    cur.execute("SELECT fu,em,ts FROM m WHERE tu=? AND d=0", (u,))
    ms = cur.fetchall()
    if ms:
        cur.execute("UPDATE m SET d=1 WHERE tu=?", (u,))
        c.commit()
        emit('om', {'m': [{'f': m[0], 'e': m[1], 'ts': m[2]} for m in ms]})
    c.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("=" * 40)
    print("ZET SERVER RUNNING")
    print(f"PORT: {port}")
    print("=" * 40)
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
