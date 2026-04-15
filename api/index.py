from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import base64
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
# Allow CORS for the custom headers required by the protocol
CORS(app, allow_headers=["Content-Type", "clientId", "timestamp", "sign", "ngrok-skip-browser-warning"])

# Vercel acts as a proxy, so we must tell Flask to trust its headers to get the correct URL
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# --- Configuration ---
CLIENT_ID = "ext-sys"
SIGN_KEY = "f44c34c04adfe1b08be1307b27f85e4522fd4e3f8104541c"
ENCRYPT_KEY_B64 = "cfhQRNfNrYbVxxvWTrrF2Q=="

# --- Mock Database ---
MOCK_DB = {
    "76057231": "111111a",  
    "89100001": "RealSecret123" 
}

# --- Crypto Helper Functions ---
def decrypt_aes(encrypted_b64, key_b64):
    key = base64.b64decode(key_b64)
    encrypted_bytes = base64.b64decode(encrypted_b64)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_bytes = unpad(decrypted_padded, AES.block_size)
    return json.loads(decrypted_bytes.decode('utf-8'))

def encrypt_aes(data_dict, key_b64):
    key = base64.b64decode(key_b64)
    raw_data = json.dumps(data_dict, separators=(',', ':')).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(raw_data, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def verify_signature(url, encrypted_req_string, client_id, timestamp, incoming_sign):
    body_str = f'{{"req"="{encrypted_req_string}"}}'
    string_to_sign = f"{url}?body={body_str}&clientId={client_id}&timestamp={timestamp}{SIGN_KEY}"
    
    md5_hash = hashlib.md5()
    md5_hash.update(string_to_sign.encode('utf-8'))
    return md5_hash.hexdigest() == incoming_sign

# --- API Endpoint ---
@app.route('/user/login', methods=['POST'])
def login():
    client_id = request.headers.get('clientId')
    timestamp = request.headers.get('timestamp')
    incoming_sign = request.headers.get('sign')
    
    body = request.get_json()
    encrypted_req = body.get('req')

    # Get the dynamic Vercel URL
    current_url = request.base_url 

    if not verify_signature(current_url, encrypted_req, client_id, timestamp, incoming_sign):
        return jsonify({"code": 403, "msg": "Invalid Signature", "data": ""}), 403

    try:
        payload = decrypt_aes(encrypted_req, ENCRYPT_KEY_B64)
    except Exception as e:
        return jsonify({"code": 400, "msg": "Decryption Failed", "data": ""}), 400

    user = payload.get('user')
    password = payload.get('pass')

    response_data = {}
    if user not in MOCK_DB:
        code, msg = 404, "User doesn't exist"
    elif MOCK_DB[user] != password:
        code, msg = 401, "Wrong password"
    else:
        code, msg = 200, "success"
        response_data = {"token": "dummy_jwt_token_12345", "userId": user}

    encrypted_response_data = encrypt_aes(response_data, ENCRYPT_KEY_B64) if response_data else ""

    return jsonify({
        "code": code,
        "msg": msg,
        "data": encrypted_response_data
    })

# NOTE: app.run() is completely removed! Vercel manages the entry point.