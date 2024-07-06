# Kelompok "APA YAHH"

from flask import Flask, render_template, request
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
import base64
import secrets

app = Flask(__name__)


# Key

MASTER_KEY_AES = secrets.token_bytes(16)
MASTER_KEY_DES = secrets.token_bytes(8)
MASTER_KEY_BLOWFISH = secrets.token_bytes(16)

# Encrypt & Decrypt Master Key dengan AES

def encrypt_key_aes(key, master_key):
    cipher = AES.new(master_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(key, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_key_aes(data, master_key):
    iv = base64.b64decode(data[:24])
    ct = base64.b64decode(data[24:])
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    key = unpad(cipher.decrypt(ct), AES.block_size)
    return key

# Encrypt & Decrypt Master Key dengan DES

def encrypt_key_des(key, master_key):
    cipher = DES.new(master_key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(key, DES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_key_des(data, master_key):
    iv = base64.b64decode(data[:12])
    ct = base64.b64decode(data[12:])
    cipher = DES.new(master_key, DES.MODE_CBC, iv)
    key = unpad(cipher.decrypt(ct), DES.block_size)
    return key

# Encrypt & Decrypt Master Key dengan BLOWFISH

def encrypt_key_blowfish(key, master_key):
    cipher = Blowfish.new(master_key, Blowfish.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(key, Blowfish.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_key_blowfish(data, master_key):
    iv = base64.b64decode(data[:12])
    ct = base64.b64decode(data[12:])
    cipher = Blowfish.new(master_key, Blowfish.MODE_CBC, iv)
    key = unpad(cipher.decrypt(ct), Blowfish.block_size)
    return key

# Data

KEY_AES = encrypt_key_aes(secrets.token_bytes(16), MASTER_KEY_AES)
KEY_DES = encrypt_key_des(secrets.token_bytes(8), MASTER_KEY_DES)
KEY_BLOWFISH = encrypt_key_blowfish(secrets.token_bytes(8), MASTER_KEY_BLOWFISH)

# Encrypt & Decrypt text dengan AES

def encrypt_aes(data):
    key = decrypt_key_aes(KEY_AES, MASTER_KEY_AES)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_aes(data):
    try:
        key = decrypt_key_aes(KEY_AES, MASTER_KEY_AES)
        iv = base64.b64decode(data[:24])
        ct = base64.b64decode(data[24:])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except ValueError as e:
        return str(e)

# Encrypt & Decrypt text dengan DES

def encrypt_des(data):
    key = decrypt_key_des(KEY_DES, MASTER_KEY_DES)
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), DES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_des(data):
    try:
        key = decrypt_key_des(KEY_DES, MASTER_KEY_DES)
        iv = base64.b64decode(data[:12])
        ct = base64.b64decode(data[12:])
        cipher = DES.new(key, DES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), DES.block_size)
        return pt.decode('utf-8')
    except ValueError as e:
        return str(e)

# Encrypt & Decrypt text dengan BLOWFISH

def encrypt_blowfish(data):
    key = decrypt_key_blowfish(KEY_BLOWFISH, MASTER_KEY_BLOWFISH)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), Blowfish.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_blowfish(data):
    try:
        key = decrypt_key_blowfish(KEY_BLOWFISH, MASTER_KEY_BLOWFISH)
        iv = base64.b64decode(data[:12])
        ct = base64.b64decode(data[12:])
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), Blowfish.block_size)
        return pt.decode('utf-8')
    except ValueError as e:
        return str(e)

# Peroses Encrypt

def encrypt(data):
    encrypted = encrypt_aes(data)
    encrypted = encrypt_des(encrypted)
    encrypted = encrypt_blowfish(encrypted)
    return encrypted

# Peroses Decrypt

def decrypt(data):
    decrypted = decrypt_blowfish(data)
    decrypted = decrypt_des(decrypted)
    decrypted = decrypt_aes(decrypted)
    return decrypted

# Root App

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    if request.method == 'POST':
        if 'encrypt' in request.form:
            plaintext = request.form['text']
            encrypted_text = encrypt(plaintext)
            result = encrypted_text
        elif 'decrypt' in request.form:
            encrypted_text = request.form['text']
            decrypted_text = decrypt(encrypted_text)
            result = decrypted_text
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)

# Kelompok "APA YAHH"