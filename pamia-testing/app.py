import sqlite3
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import hashlib
import struct
import secrets
import time as time_module

app = Flask(__name__, static_folder='.')
app.secret_key = 'p4n4d3r14-s3cr3t-k3y-2026'
CORS(app, supports_credentials=True)

DATABASE = 'panaderia.db'

RP_ID = 'localhost'
RP_ORIGIN = 'http://localhost:5000'

COLORES_DIAS = {
    0: "Lunes - Verde",
    1: "Martes - Azul",
    2: "Miércoles - Amarillo",
    3: "Jueves - Naranja",
    4: "Viernes - Morado",
    5: "Sábado - Rosado",
    6: "Domingo - Rojo"
}

_pending_challenges = {}

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            nombre_completo TEXT NOT NULL,
            rol TEXT NOT NULL CHECK(rol IN ('admin', 'panadero')),
            activo INTEGER DEFAULT 1
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo TEXT UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            horas_duracion INTEGER NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            producto TEXT NOT NULL,
            codigo_producto TEXT,
            color TEXT NOT NULL,
            fecha_vencimiento TEXT NOT NULL,
            estado TEXT DEFAULT 'En Vitrina'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS movimientos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lote_id INTEGER,
            producto TEXT NOT NULL,
            tipo TEXT NOT NULL CHECK(tipo IN ('recibido', 'vendido', 'vencido')),
            cantidad INTEGER DEFAULT 1,
            fecha TEXT NOT NULL,
            FOREIGN KEY (lote_id) REFERENCES lotes(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS huellas_credenciales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            credential_id TEXT UNIQUE NOT NULL,
            public_key BLOB NOT NULL,
            sign_count INTEGER DEFAULT 0,
            aaguid TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
        )
    ''')

    admin_exists = cursor.execute("SELECT id FROM usuarios WHERE username = ?", ("admin",)).fetchone()
    if not admin_exists:
        admin_hash = generate_password_hash("admin123")
        cursor.execute("INSERT INTO usuarios (username, password_hash, nombre_completo, rol, activo) VALUES (?, ?, ?, ?, ?)",
                       ("admin", admin_hash, "Administrador General", "admin", 1))

    panadero_exists = cursor.execute("SELECT id FROM usuarios WHERE username = ?", ("panadero1",)).fetchone()
    if not panadero_exists:
        panadero_hash = generate_password_hash("panadero123")
        cursor.execute("INSERT INTO usuarios (username, password_hash, nombre_completo, rol, activo) VALUES (?, ?, ?, ?, ?)",
                       ("panadero1", panadero_hash, "Panadero Principal", "panadero", 1))

    productos_exist = cursor.execute("SELECT COUNT(*) FROM productos").fetchone()[0]
    if productos_exist == 0:
        productos_iniciales = [
            ("78011111", "Pie de Limón Premium", 72),
            ("78022222", "Tarta de Tres Leches", 48),
            ("78033333", "Pan de Pascua / Especial", 120),
            ("78044444", "Croissant de Mantequilla", 36),
            ("78055555", "Muffin de Arándano", 48),
        ]
        for codigo, nombre, horas in productos_iniciales:
            cursor.execute("INSERT INTO productos (codigo, nombre, horas_duracion) VALUES (?, ?, ?)",
                          (codigo, nombre, horas))

    conn.commit()

    try:
        conn.execute("ALTER TABLE lotes ADD COLUMN codigo_producto TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "No autorizado"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "No autorizado"}), 401
        conn = get_db()
        user = conn.execute("SELECT rol FROM usuarios WHERE id = ?", (session['user_id'],)).fetchone()
        conn.close()
        if not user or user['rol'] != 'admin':
            return jsonify({"error": "Se requieren permisos de administrador"}), 403
        return f(*args, **kwargs)
    return decorated

# --- WebAuthn (Huella Dactilar) ---

def base64url_encode_bytes(data):
    import base64
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def base64url_decode_str(s):
    import base64
    s = s.replace('-', '+').replace('_', '/')
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.b64decode(s)

def cbor_decode(data):
    pos = [0]

    def _decode():
        if pos[0] >= len(data):
            raise ValueError("Unexpected end of CBOR data")
        initial_byte = data[pos[0]]
        pos[0] += 1
        major_type = initial_byte >> 5
        argument = initial_byte & 0x1f

        if argument < 24:
            additional = argument
        elif argument == 24:
            additional = data[pos[0]]
            pos[0] += 1
        elif argument == 25:
            additional = struct.unpack_from('>H', data, pos[0])[0]
            pos[0] += 2
        elif argument == 26:
            additional = struct.unpack_from('>I', data, pos[0])[0]
            pos[0] += 4
        elif argument == 27:
            additional = struct.unpack_from('>Q', data, pos[0])[0]
            pos[0] += 8
        else:
            raise ValueError(f"Indefinite length or reserved argument: {argument}")

        if major_type == 0:
            return additional
        elif major_type == 1:
            return -1 - additional
        elif major_type == 2:
            chunk = data[pos[0]:pos[0] + additional]
            pos[0] += additional
            return chunk
        elif major_type == 3:
            chunk = data[pos[0]:pos[0] + additional].decode('utf-8')
            pos[0] += additional
            return chunk
        elif major_type == 4:
            return [_decode() for _ in range(additional)]
        elif major_type == 5:
            d = {}
            for _ in range(additional):
                k = _decode()
                v = _decode()
                d[k] = v
            return d
        elif major_type == 7:
            if argument == 20:
                return False
            elif argument == 21:
                return True
            elif argument == 22:
                return None
            return additional
        else:
            raise ValueError(f"Unsupported CBOR major type: {major_type}")

    return _decode()

def parse_cose_public_key(cose_key):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1, EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    kty = cose_key.get(1)
    if kty == 2:
        crv = cose_key.get(-1)
        x = cose_key.get(-2)
        y = cose_key.get(-3)
        if crv == 7:
            pub_numbers = EllipticCurvePublicNumbers(
                x=int.from_bytes(x, 'big'),
                y=int.from_bytes(y, 'big'),
                curve=SECP256R1()
            )
            return pub_numbers.public_key()
    elif kty == 3:
        n = cose_key.get(-1)
        e = cose_key.get(-2)
        pub_numbers = RSAPublicNumbers(
            e=int.from_bytes(e, 'big'),
            n=int.from_bytes(n, 'big')
        )
        return pub_numbers.public_key()

    raise ValueError(f"Unsupported COSE key type: {kty}")

def serialize_cose_public_key(cose_key):
    import json
    result = {}
    for k, v in cose_key.items():
        if isinstance(v, bytes):
            result[str(k)] = base64url_encode_bytes(v)
        else:
            result[str(k)] = v
    return json.dumps(result)

def deserialize_cose_public_key(s):
    import json
    raw = json.loads(s)
    result = {}
    for k, v in raw.items():
        key = int(k)
        if isinstance(v, str) and key in (-1, -2, -3):
            result[key] = base64url_decode_str(v)
        else:
            result[key] = v
    return result

def verify_attestation_public_key(att_obj):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, ECDSA
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives import hashes

    authenticator_data = att_obj.get('authData')
    if not authenticator_data or len(authenticator_data) < 37:
        raise ValueError("Invalid authenticator data")

    rp_id_hash = authenticator_data[:32]
    expected_rp_hash = hashlib.sha256(RP_ID.encode('utf-8')).digest()
    if rp_id_hash != expected_rp_hash:
        raise ValueError("RP ID hash mismatch")

    flags = authenticator_data[32]
    sign_count = struct.unpack_from('>I', authenticator_data, 33)[0]

    if not (flags & 0x40):
        raise ValueError("AT flag not set in attestation")

    attested_data = authenticator_data[37:]
    if len(attested_data) < 18:
        raise ValueError("Invalid attested credential data")

    aaguid = attested_data[:16]
    cred_id_len = struct.unpack_from('>H', attested_data, 16)[0]
    credential_id = attested_data[18:18 + cred_id_len]
    cose_public_key_bytes = attested_data[18 + cred_id_len:]

    cose_key = cbor_decode(cose_public_key_bytes)
    public_key = parse_cose_public_key(cose_key)

    return credential_id, public_key, sign_count, aaguid, cose_key

def verify_attestation(attestation_object_b64, client_data_json_b64):
    attestation_object = cbor_decode(base64url_decode_str(attestation_object_b64))
    fmt = attestation_object.get('fmt', 'none')

    credential_id, public_key, sign_count, aaguid, cose_key = verify_attestation_public_key(attestation_object)

    return credential_id, public_key, sign_count, aaguid, cose_key

def verify_assertion(authenticator_data_b64, client_data_json_b64, signature_b64, public_key, expected_challenge):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, ECDSA
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives import hashes

    client_data = __import__('json').loads(base64url_decode_str(client_data_json_b64))
    if client_data.get('type') != 'webauthn.get':
        raise ValueError("Invalid client data type")
    if client_data.get('origin') != RP_ORIGIN:
        raise ValueError("Invalid origin")

    received_challenge = client_data.get('challenge', '')
    if received_challenge != expected_challenge:
        raise ValueError("Challenge mismatch")

    authenticator_data = base64url_decode_str(authenticator_data_b64)
    if len(authenticator_data) < 37:
        raise ValueError("Invalid authenticator data")

    rp_id_hash = authenticator_data[:32]
    expected_rp_hash = hashlib.sha256(RP_ID.encode('utf-8')).digest()
    if rp_id_hash != expected_rp_hash:
        raise ValueError("RP ID hash mismatch")

    flags = authenticator_data[32]
    if not (flags & 0x01):
        raise ValueError("User presence flag not set")

    client_data_hash = hashlib.sha256(base64url_decode_str(client_data_json_b64)).digest()
    signed_data = authenticator_data + client_data_hash
    signature = base64url_decode_str(signature_b64)

    if isinstance(public_key, EllipticCurvePublicKey):
        public_key.verify(signature, signed_data, ECDSA(hashes.SHA256()))
    elif isinstance(public_key, RSAPublicKey):
        public_key.verify(signature, signed_data, PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("Unsupported public key type")

    new_sign_count = struct.unpack_from('>I', authenticator_data, 33)[0]
    return new_sign_count

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    conn = get_db()
    user = conn.execute("SELECT * FROM usuarios WHERE username = ? AND activo = 1", (username,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({"error": "Usuario o contraseña incorrectos"}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']
    session['rol'] = user['rol']
    session['nombre'] = user['nombre_completo']

    return jsonify({
        "id": user['id'],
        "username": user['username'],
        "nombre_completo": user['nombre_completo'],
        "rol": user['rol']
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"status": "logged_out"})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_me():
    conn = get_db()
    user = conn.execute("SELECT id, username, nombre_completo, rol FROM usuarios WHERE id = ?",
                       (session['user_id'],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return jsonify({"error": "Usuario no encontrado"}), 401
    return jsonify({
        "id": user['id'],
        "username": user['username'],
        "nombre_completo": user['nombre_completo'],
        "rol": user['rol']
    })

# --- WebAuthn Routes ---

@app.route('/api/auth/huella/register-options', methods=['POST'])
@login_required
@admin_required
def huella_register_options():
    data = request.json
    target_user_id = data.get('user_id')

    if not target_user_id:
        return jsonify({"error": "user_id requerido"}), 400

    conn = get_db()
    user = conn.execute("SELECT id, username, nombre_completo FROM usuarios WHERE id = ? AND activo = 1",
                       (target_user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Usuario no encontrado"}), 404

    existing = conn.execute("SELECT credential_id FROM huellas_credenciales WHERE usuario_id = ?",
                           (target_user_id,)).fetchall()
    conn.close()

    challenge = secrets.token_bytes(32)
    challenge_b64 = base64url_encode_bytes(challenge)

    exclude_credentials = []
    for cred in existing:
        exclude_credentials.append({
            "type": "public-key",
            "id": cred['credential_id']
        })

    _pending_challenges[f"reg_{target_user_id}"] = {
        "challenge": challenge_b64,
        "expires": time_module.time() + 120
    }

    options = {
        "challenge": challenge_b64,
        "rp": {
            "id": RP_ID,
            "name": "Panadería - Sistema de Gestión"
        },
        "user": {
            "id": base64url_encode_bytes(str(target_user_id).encode('utf-8')),
            "name": user['username'],
            "displayName": user['nombre_completo']
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257}
        ],
        "timeout": 120000,
        "attestation": "none",
        "excludeCredentials": exclude_credentials,
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred"
        }
    }

    return jsonify(options)

@app.route('/api/auth/huella/register', methods=['POST'])
@login_required
@admin_required
def huella_register():
    data = request.json
    target_user_id = data.get('user_id')
    credential_id = data.get('id')
    attestation_object_b64 = data.get('attestationObject')
    client_data_json_b64 = data.get('clientDataJSON')

    if not all([target_user_id, credential_id, attestation_object_b64, client_data_json_b64]):
        return jsonify({"error": "Datos incompletos"}), 400

    challenge_key = f"reg_{target_user_id}"
    pending = _pending_challenges.get(challenge_key)
    if not pending:
        return jsonify({"error": "No hay challenge pendiente. Intente nuevamente."}), 400

    if time_module.time() > pending['expires']:
        del _pending_challenges[challenge_key]
        return jsonify({"error": "Challenge expirado. Intente nuevamente."}), 400

    client_data = __import__('json').loads(base64url_decode_str(client_data_json_b64))
    if client_data.get('type') != 'webauthn.create':
        return jsonify({"error": "Tipo de operación inválido"}), 400
    if client_data.get('origin') != RP_ORIGIN:
        return jsonify({"error": "Origen inválido"}), 400
    if client_data.get('challenge') != pending['challenge']:
        return jsonify({"error": "Challenge inválido"}), 400

    try:
        cred_id, public_key, sign_count, aaguid, cose_key = verify_attestation(attestation_object_b64, client_data_json_b64)
    except Exception as e:
        return jsonify({"error": f"Error de verificación: {str(e)}"}), 400

    cred_id_b64 = base64url_encode_bytes(cred_id)

    if cred_id_b64 != credential_id:
        return jsonify({"error": "Credential ID mismatch"}), 400

    del _pending_challenges[challenge_key]

    conn = get_db()
    existing = conn.execute("SELECT id FROM huellas_credenciales WHERE credential_id = ?",
                           (cred_id_b64,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Esta huella ya está registrada"}), 400

    aaguid_hex = aaguid.hex() if isinstance(aaguid, bytes) else str(aaguid)
    public_key_blob = serialize_cose_public_key(cose_key).encode('utf-8')

    conn.execute(
        "INSERT INTO huellas_credenciales (usuario_id, credential_id, public_key, sign_count, aaguid, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (target_user_id, cred_id_b64, public_key_blob, sign_count, aaguid_hex, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "registered", "credential_id": cred_id_b64}), 201

@app.route('/api/auth/huella/auth-options', methods=['POST'])
def huella_auth_options():
    conn = get_db()
    credentials = conn.execute("""
        SELECT h.credential_id, h.usuario_id, u.username, u.nombre_completo
        FROM huellas_credenciales h
        JOIN usuarios u ON h.usuario_id = u.id
        WHERE u.activo = 1
    """).fetchall()
    conn.close()

    if not credentials:
        return jsonify({"error": "No hay huellas registradas en el sistema"}), 404

    challenge = secrets.token_bytes(32)
    challenge_b64 = base64url_encode_bytes(challenge)

    allow_credentials = []
    for cred in credentials:
        allow_credentials.append({
            "type": "public-key",
            "id": cred['credential_id']
        })

    challenge_id = base64url_encode_bytes(secrets.token_bytes(16))
    _pending_challenges[f"auth_{challenge_id}"] = {
        "challenge": challenge_b64,
        "credentials": {cred['credential_id']: cred['usuario_id'] for cred in credentials},
        "expires": time_module.time() + 120
    }

    options = {
        "challenge": challenge_b64,
        "timeout": 120000,
        "rpId": RP_ID,
        "allowCredentials": allow_credentials,
        "userVerification": "preferred"
    }

    return jsonify({"options": options, "challenge_id": challenge_id})

@app.route('/api/auth/huella/authenticate', methods=['POST'])
def huella_authenticate():
    data = request.json
    credential_id = data.get('id')
    authenticator_data_b64 = data.get('authenticatorData')
    client_data_json_b64 = data.get('clientDataJSON')
    signature_b64 = data.get('signature')
    challenge_id = data.get('challenge_id')

    if not all([credential_id, authenticator_data_b64, client_data_json_b64, signature_b64, challenge_id]):
        return jsonify({"error": "Datos incompletos"}), 400

    challenge_key = f"auth_{challenge_id}"
    pending = _pending_challenges.get(challenge_key)
    if not pending:
        return jsonify({"error": "No hay challenge pendiente. Intente nuevamente."}), 400

    if time_module.time() > pending['expires']:
        del _pending_challenges[challenge_key]
        return jsonify({"error": "Challenge expirado. Intente nuevamente."}), 400

    user_id = pending['credentials'].get(credential_id)
    if not user_id:
        del _pending_challenges[challenge_key]
        return jsonify({"error": "Credencial no reconocida"}), 401

    conn = get_db()
    cred = conn.execute("SELECT * FROM huellas_credenciales WHERE credential_id = ? AND usuario_id = ?",
                       (credential_id, user_id)).fetchone()
    if not cred:
        conn.close()
        del _pending_challenges[challenge_key]
        return jsonify({"error": "Credencial no encontrada"}), 401

    public_key = deserialize_cose_public_key(cred['public_key'].decode('utf-8'))

    try:
        new_sign_count = verify_assertion(
            authenticator_data_b64,
            client_data_json_b64,
            signature_b64,
            public_key,
            pending['challenge']
        )
    except Exception as e:
        conn.close()
        del _pending_challenges[challenge_key]
        return jsonify({"error": f"Verificación fallida: {str(e)}"}), 401

    if new_sign_count > 0 and cred['sign_count'] > 0 and new_sign_count <= cred['sign_count']:
        conn.close()
        del _pending_challenges[challenge_key]
        return jsonify({"error": "Replay detectado. Posible intento de fraude."}), 401

    conn.execute("UPDATE huellas_credenciales SET sign_count = ? WHERE id = ?", (new_sign_count, cred['id']))
    conn.commit()

    user = conn.execute("SELECT id, username, nombre_completo, rol FROM usuarios WHERE id = ? AND activo = 1",
                       (user_id,)).fetchone()
    conn.close()

    del _pending_challenges[challenge_key]

    if not user:
        return jsonify({"error": "Usuario inactivo o no encontrado"}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']
    session['rol'] = user['rol']
    session['nombre'] = user['nombre_completo']

    return jsonify({
        "id": user['id'],
        "username": user['username'],
        "nombre_completo": user['nombre_completo'],
        "rol": user['rol']
    })

@app.route('/api/usuarios/<int:usuario_id>/huellas', methods=['GET'])
@login_required
@admin_required
def get_huellas_usuario(usuario_id):
    conn = get_db()
    huellas = conn.execute(
        "SELECT id, credential_id, sign_count, created_at FROM huellas_credenciales WHERE usuario_id = ? ORDER BY created_at DESC",
        (usuario_id,)
    ).fetchall()
    conn.close()
    return jsonify([{
        "id": h['id'],
        "credential_id": h['credential_id'],
        "sign_count": h['sign_count'],
        "created_at": h['created_at']
    } for h in huellas])

@app.route('/api/usuarios/<int:usuario_id>/huellas/<int:huella_id>', methods=['DELETE'])
@login_required
@admin_required
def eliminar_huella(usuario_id, huella_id):
    conn = get_db()
    huella = conn.execute("SELECT * FROM huellas_credenciales WHERE id = ? AND usuario_id = ?",
                         (huella_id, usuario_id)).fetchone()
    if not huella:
        conn.close()
        return jsonify({"error": "Huella no encontrada"}), 404
    conn.execute("DELETE FROM huellas_credenciales WHERE id = ?", (huella_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})

# --- Product Routes (Admin only) ---

@app.route('/api/productos', methods=['GET'])
@login_required
def get_productos():
    conn = get_db()
    productos = conn.execute("SELECT id, codigo, nombre, horas_duracion FROM productos ORDER BY nombre").fetchall()
    conn.close()
    return jsonify([{
        "id": p['id'],
        "codigo": p['codigo'],
        "nombre": p['nombre'],
        "horas_duracion": p['horas_duracion']
    } for p in productos])

@app.route('/api/productos', methods=['POST'])
@admin_required
def add_producto():
    data = request.json
    codigo = data.get('codigo', '').strip()
    nombre = data.get('nombre', '').strip()
    horas = data.get('horas_duracion')

    if not codigo or not nombre or not horas:
        return jsonify({"error": "Todos los campos son requeridos"}), 400

    try:
        horas = int(horas)
    except (ValueError, TypeError):
        return jsonify({"error": "Horas debe ser un número válido"}), 400

    conn = get_db()
    exists = conn.execute("SELECT id FROM productos WHERE codigo = ?", (codigo,)).fetchone()
    if exists:
        conn.close()
        return jsonify({"error": f"El código '{codigo}' ya existe en el sistema"}), 400

    try:
        conn.execute("INSERT INTO productos (codigo, nombre, horas_duracion) VALUES (?, ?, ?)",
                    (codigo, nombre, horas))
        conn.commit()
        nuevo_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return jsonify({"id": nuevo_id, "codigo": codigo, "nombre": nombre, "horas_duracion": horas}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "El código ya existe"}), 400

@app.route('/api/productos/<int:producto_id>', methods=['PUT'])
@admin_required
def update_producto(producto_id):
    data = request.json
    conn = get_db()
    producto = conn.execute("SELECT * FROM productos WHERE id = ?", (producto_id,)).fetchone()
    if not producto:
        conn.close()
        return jsonify({"error": "Producto no encontrado"}), 404

    codigo = data.get('codigo', producto['codigo']).strip()
    nombre = data.get('nombre', producto['nombre']).strip()
    horas = data.get('horas_duracion', producto['horas_duracion'])

    try:
        horas = int(horas)
    except (ValueError, TypeError):
        conn.close()
        return jsonify({"error": "Horas debe ser un número válido"}), 400

    duplicado = conn.execute("SELECT id FROM productos WHERE codigo = ? AND id != ?", (codigo, producto_id)).fetchone()
    if duplicado:
        conn.close()
        return jsonify({"error": f"El código '{codigo}' ya está en uso por otro producto"}), 400

    conn.execute("UPDATE productos SET codigo = ?, nombre = ?, horas_duracion = ? WHERE id = ?",
                (codigo, nombre, horas, producto_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated"})

@app.route('/api/productos/<int:producto_id>', methods=['DELETE'])
@admin_required
def delete_producto(producto_id):
    conn = get_db()
    producto = conn.execute("SELECT * FROM productos WHERE id = ?", (producto_id,)).fetchone()
    if not producto:
        conn.close()
        return jsonify({"error": "Producto no encontrado"}), 404
    conn.execute("DELETE FROM productos WHERE id = ?", (producto_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})

# --- User Routes (Admin only) ---

@app.route('/api/usuarios', methods=['GET'])
@admin_required
def get_usuarios():
    conn = get_db()
    usuarios = conn.execute("SELECT id, username, nombre_completo, rol, activo FROM usuarios ORDER BY nombre_completo").fetchall()
    conn.close()
    return jsonify([{
        "id": u['id'],
        "username": u['username'],
        "nombre_completo": u['nombre_completo'],
        "rol": u['rol'],
        "activo": bool(u['activo'])
    } for u in usuarios])

@app.route('/api/usuarios', methods=['POST'])
@admin_required
def add_usuario():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    nombre_completo = data.get('nombre_completo', '').strip()
    rol = data.get('rol', 'panadero')

    if not username or not password or not nombre_completo:
        return jsonify({"error": "Todos los campos son requeridos"}), 400
    if rol not in ('admin', 'panadero'):
        return jsonify({"error": "Rol inválido"}), 400

    conn = get_db()
    exists = conn.execute("SELECT id FROM usuarios WHERE username = ?", (username,)).fetchone()
    if exists:
        conn.close()
        return jsonify({"error": f"El usuario '{username}' ya existe"}), 400

    password_hash = generate_password_hash(password)
    conn.execute("INSERT INTO usuarios (username, password_hash, nombre_completo, rol, activo) VALUES (?, ?, ?, ?, 1)",
                (username, password_hash, nombre_completo, rol))
    conn.commit()
    nuevo_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return jsonify({"id": nuevo_id, "username": username, "nombre_completo": nombre_completo, "rol": rol, "activo": True}), 201

@app.route('/api/usuarios/<int:usuario_id>', methods=['PUT'])
@admin_required
def update_usuario(usuario_id):
    data = request.json
    conn = get_db()
    user = conn.execute("SELECT * FROM usuarios WHERE id = ?", (usuario_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Usuario no encontrado"}), 404

    nombre_completo = data.get('nombre_completo', user['nombre_completo']).strip()
    rol = data.get('rol', user['rol'])

    if 'activo' in data:
        activo = 1 if data['activo'] else 0
    else:
        activo = user['activo']

    if rol not in ('admin', 'panadero'):
        conn.close()
        return jsonify({"error": "Rol inválido"}), 400

    conn.execute("UPDATE usuarios SET nombre_completo = ?, rol = ?, activo = ? WHERE id = ?",
                (nombre_completo, rol, activo, usuario_id))

    if data.get('password'):
        password_hash = generate_password_hash(data['password'])
        conn.execute("UPDATE usuarios SET password_hash = ? WHERE id = ?", (password_hash, usuario_id))

    conn.commit()
    conn.close()
    return jsonify({"status": "updated"})

@app.route('/api/usuarios/<int:usuario_id>', methods=['DELETE'])
@admin_required
def delete_usuario(usuario_id):
    if usuario_id == session['user_id']:
        return jsonify({"error": "No puedes eliminarte a ti mismo"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM usuarios WHERE id = ?", (usuario_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Usuario no encontrado"}), 404
    conn.execute("DELETE FROM usuarios WHERE id = ?", (usuario_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})

# --- Product lookup (authenticated) ---

@app.route('/api/producto/<codigo_barras>', methods=['GET'])
@login_required
def buscar_por_codigo(codigo_barras):
    conn = get_db()
    prod = conn.execute("SELECT * FROM productos WHERE codigo = ?", (codigo_barras,)).fetchone()
    conn.close()

    if not prod:
        return jsonify({"error": "Código de barras no registrado"}), 404

    dia_semana_hoy = datetime.now().weekday()
    color_automatico = COLORES_DIAS[dia_semana_hoy]

    return jsonify({
        "id": prod['id'],
        "codigo": prod['codigo'],
        "nombre": prod['nombre'],
        "horas_duracion": prod['horas_duracion'],
        "color_asignado": color_automatico
    })

# --- Lotes Routes ---

@app.route('/api/lotes', methods=['GET'])
@login_required
def get_lotes():
    conn = get_db()
    rows = conn.execute("SELECT id, producto, codigo_producto, color, fecha_vencimiento, estado FROM lotes").fetchall()
    conn.close()

    ahora = datetime.now()
    lotes = []

    for r in rows:
        try:
            fecha_venc = datetime.strptime(r['fecha_vencimiento'], '%Y-%m-%d %H:%M')
        except ValueError:
            continue
        tiempo_restante = fecha_venc - ahora

        alerta = bool(timedelta(hours=0) < tiempo_restante <= timedelta(hours=24) and r['estado'] == 'En Vitrina')

        lotes.append({
            "id": r['id'],
            "producto": r['producto'],
            "codigo_producto": r['codigo_producto'],
            "color": r['color'],
            "fecha_vencimiento": r['fecha_vencimiento'],
            "estado": r['estado'],
            "alerta": alerta
        })

    return jsonify(lotes)

@app.route('/api/lotes', methods=['POST'])
@login_required
def add_lote():
    data = request.json
    producto = data.get('producto')
    codigo_producto = data.get('codigo_producto')
    color = data.get('color')
    horas = int(data.get('horas_duracion', 72))

    fecha_venc = datetime.now() + timedelta(hours=horas)
    fecha_venc_str = fecha_venc.strftime('%Y-%m-%d %H:%M')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO lotes (producto, codigo_producto, color, fecha_vencimiento) VALUES (?, ?, ?, ?)",
                   (producto, codigo_producto, color, fecha_venc_str))
    lote_id = cursor.lastrowid

    cursor.execute("INSERT INTO movimientos (lote_id, producto, tipo, cantidad, fecha) VALUES (?, ?, 'recibido', 1, ?)",
                   (lote_id, producto, datetime.now().strftime('%Y-%m-%d %H:%M')))
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "id": lote_id}), 201

@app.route('/api/lotes/<int:lote_id>', methods=['DELETE'])
@login_required
def eliminar_lote(lote_id):
    conn = get_db()
    lote = conn.execute("SELECT * FROM lotes WHERE id = ?", (lote_id,)).fetchone()
    if not lote:
        conn.close()
        return jsonify({"error": "Lote no encontrado"}), 404

    conn.execute("DELETE FROM lotes WHERE id = ?", (lote_id,))
    conn.execute("INSERT INTO movimientos (lote_id, producto, tipo, cantidad, fecha) VALUES (?, ?, 'vendido', 1, ?)",
                 (lote_id, lote['producto'], datetime.now().strftime('%Y-%m-%d %H:%M')))
    conn.commit()
    conn.close()

    return jsonify({"status": "deleted"}), 200

@app.route('/api/lotes/<int:lote_id>/vencer', methods=['POST'])
@login_required
def marcar_vencido(lote_id):
    conn = get_db()
    lote = conn.execute("SELECT * FROM lotes WHERE id = ?", (lote_id,)).fetchone()
    if not lote:
        conn.close()
        return jsonify({"error": "Lote no encontrado"}), 404

    conn.execute("UPDATE lotes SET estado = 'Vencido' WHERE id = ?", (lote_id,))
    conn.execute("INSERT INTO movimientos (lote_id, producto, tipo, cantidad, fecha) VALUES (?, ?, 'vencido', 1, ?)",
                 (lote_id, lote['producto'], datetime.now().strftime('%Y-%m-%d %H:%M')))
    conn.commit()
    conn.close()

    return jsonify({"status": "vencido"})

# --- Report Routes (Admin only) ---

@app.route('/api/reportes', methods=['GET'])
@admin_required
def get_reportes():
    conn = get_db()

    periodo = request.args.get('periodo', 'todo')
    desde = request.args.get('desde')
    hasta = request.args.get('hasta')

    fecha_condition = ""
    params = []

    if periodo == 'hoy':
        fecha_condition = "AND DATE(fecha) = ?"
        params = [datetime.now().strftime('%Y-%m-%d')]
    elif periodo == 'semana':
        inicio = (datetime.now() - timedelta(days=datetime.now().weekday())).strftime('%Y-%m-%d')
        fecha_condition = "AND DATE(fecha) >= ?"
        params = [inicio]
    elif periodo == 'mes':
        inicio = datetime.now().replace(day=1).strftime('%Y-%m-%d')
        fecha_condition = "AND DATE(fecha) >= ?"
        params = [inicio]
    elif periodo == 'personalizado' and desde and hasta:
        fecha_condition = "AND DATE(fecha) BETWEEN ? AND ?"
        params = [desde, hasta]

    def contar(tipo):
        row = conn.execute(f"SELECT COUNT(*) as total FROM movimientos WHERE tipo = ? {fecha_condition}", [tipo] + params).fetchone()
        return row['total'] if row else 0

    recibidos = contar('recibido')
    vendidos = contar('vendido')
    vencidos = contar('vencido')

    en_stock_row = conn.execute("SELECT COUNT(*) as total FROM lotes WHERE estado = 'En Vitrina'").fetchone()
    en_stock = en_stock_row['total'] if en_stock_row else 0

    top_recibidos = conn.execute("""
        SELECT producto, COUNT(*) as total FROM movimientos WHERE tipo = 'recibido'
        GROUP BY producto ORDER BY total DESC LIMIT 10
    """).fetchall()

    top_vendidos = conn.execute("""
        SELECT producto, COUNT(*) as total FROM movimientos WHERE tipo = 'vendido'
        GROUP BY producto ORDER BY total DESC LIMIT 10
    """).fetchall()

    conn.close()

    return jsonify({
        "recibidos": recibidos,
        "vendidos": vendidos,
        "vencidos": vencidos,
        "en_stock": en_stock,
        "top_recibidos": [{"producto": r['producto'], "total": r['total']} for r in top_recibidos],
        "top_vendidos": [{"producto": r['producto'], "total": r['total']} for r in top_vendidos]
    })

if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)
