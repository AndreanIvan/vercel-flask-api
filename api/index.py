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
    "89100001": "RealSecret123",
    "94796811": "Tiens6811",
    "95032854": "Tiens2854",
    "76089110": "Tiens9110",
    "76074290": "Tiens4290",
    "77678685": "Tiens8685",
    "76080066": "Tiens0066",
    "76074287": "Tiens4287",
    "76081871": "Tiens1871",
    "76081959": "Tiens1959",
    "76091295": "Tiens1295",
    "95273897": "Tiens3897",
    "94376191": "Tiens6191",
    "76089469": "Tiens9469",
    "79329617": "Tiens9617",
    "76081960": "Tiens1960",
    "77816004": "Tiens6004",
    "76089650": "Tiens9650",
    "76067040": "Tiens7040",
    "94793402": "Tiens3402",
    "76081846": "Tiens1846",
    "77720292": "Tiens0292",
    "75901528": "Tiens1528",
    "77720466": "Tiens0466",
    "95406730": "Tiens6730",
    "95366666": "Tiens6666",
    "91997873": "Tiens7873",
    "76081984": "Tiens1984",
    "76081965": "Tiens1965",
    "76006150": "Tiens6150",
    "77923846": "Tiens3846",
    "77919899": "Tiens9899",
    "76035127": "Tiens5127",
    "76089163": "Tiens9163",
    "76081769": "Tiens1769",
    "76056100": "Tiens6100",
    "76073228": "Tiens3228",
    "76089401": "Tiens9401",
    "76089208": "Tiens9208",
    "77836551": "Tiens6551",
    "76081863": "Tiens1863",
    "79104011": "Tiens4011",
    "76083937": "Tiens3937",
    "77914419": "Tiens4419",
    "76079953": "Tiens9953",
    "95426125": "Tiens6125",
    "76079954": "Tiens9954",
    "89476776": "Tiens6776",
    "75953563": "Tiens3563",
    "75899341": "Tiens9341",
    "95395140": "Tiens5140",
    "76079972": "Tiens9972",
    "76044788": "Tiens4788",
    "95024665": "Tiens4665",
    "95010646": "Tiens0646",
    "77903804": "Tiens3804",
    "76022259": "Tiens2259",
    "75955511": "Tiens5511",
    "79360963": "Tiens0963",
    "94993443": "Tiens3443",
    "89902786": "Tiens2786",
    "95017906": "Tiens7906",
    "76090744": "Tiens0744",
    "76074294": "Tiens4294",
    "89969765": "Tiens9765",
    "79812033": "Tiens2033",
    "75987355": "Tiens7355",
    "76081423": "Tiens1423",
    "76081874": "Tiens1874",
    "76081876": "Tiens1876",
    "76081783": "Tiens1783",
    "76081856": "Tiens1856",
    "76081787": "Tiens1787",
    "75912869": "Tiens2869",
    "76081947": "Tiens1947",
    "76081914": "Tiens1914",
    "76053184": "Tiens3184",
    "76081799": "Tiens1799",
    "76081948": "Tiens1948",
    "76081801": "Tiens1801",
    "89761751": "Tiens1751",
    "89866516": "Tiens6516",
    "95436204": "Tiens6204",
    "89400266": "Tiens0266",
    "77623365": "Tiens3365",
    "76091203": "Tiens1203",
    "76067647": "Tiens7647",
    "76081946": "Tiens1946",
    "76081945": "Tiens1945",
    "76081789": "Tiens1789",
    "76081795": "Tiens1795",
    "76081875": "Tiens1875",
    "76090263": "Tiens0263",
    "76081738": "Tiens1738",
    "76037351": "Tiens7351",
    "76081937": "Tiens1937",
    "76081943": "Tiens1943",
    "76081929": "Tiens1929",
    "76081851": "Tiens1851",
    "76055137": "Tiens5137",
    "76081798": "Tiens1798",
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
        return jsonify({"code": 403, "msg": "Signature tidak valid", "data": ""}), 403

    try:
        payload = decrypt_aes(encrypted_req, ENCRYPT_KEY_B64)
    except Exception as e:
        return jsonify({"code": 400, "msg": "Dekripsi gagal", "data": ""}), 400

    user = payload.get('user')
    password = payload.get('pass')

    response_data = {}
    if user not in MOCK_DB:
        code, msg = 404, "Pengguna tidak ditemukan"
    elif MOCK_DB[user] != password:
        code, msg = 401, "Kata sandi salah"
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