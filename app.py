from flask import Flask, request, render_template, jsonify

def LEA(signature: str, original_data: str, append_data: str ,secret_length: int) -> tuple[bytes, bytes]:
    signature = bytes.fromhex(signature)
    original_data = original_data.encode()
    append_data = append_data.encode()
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    length = len(original_data) + secret_length
    
    def right_rotate(x: int, shift: int):
        return (x >> shift) | (x << 32 - shift) & 0xffffffff
    
    def get_padding(length: int):
        return b"\x80" + b"\x00" * ((56 - (length + 1) % 64) % 64) + (length * 8).to_bytes(8, byteorder="big")
    
    message = append_data + get_padding(length + ((56 - (length + 1) % 64) % 64) + 9 + len(append_data))
    h0, h1, h2, h3, h4, h5, h6, h7 = [int.from_bytes(signature[i : i + 4], byteorder='big') for i in range(0, len(signature), 4)]
    
    for chunk in [message [i : i + 64] for i in range(0, len(message), 64)]:
        # break chuck into sixteen 32bits big-endian words and extend to 80 words
        w = [int.from_bytes(chunk[i:i+4], byteorder="big") for i in range(0, len(chunk), 4)]
        for i in range(16, 64):
            s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)
        
        # initialize hash value for this chunk
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for i in range(64):     
            def Ch(x: int, y: int, z: int):
                res = (x & y) ^ (~x & z)
                return res & 0xffffffff
    
            def Maj(x: int, y: int, z: int):
                res = (x & y) ^ (x & z) ^ (y & z)
                return res & 0xffffffff
            
            def SIGMA0(x: int):
                res = right_rotate(x=x, shift=2) ^ right_rotate(x=x, shift=13) ^ right_rotate(x=x, shift=22)
                return res & 0xffffffff

            def SIGMA1(x: int):
                res = right_rotate(x=x, shift=6) ^ right_rotate(x=x, shift=11) ^ right_rotate(x=x, shift=25)
                return res & 0xffffffff
            
            T1 = h + SIGMA1(e) + Ch(e, f, g) + K[i] + w[i]
            T2 = SIGMA0(a) + Maj(a, b, c)
            
            h = g
            g = f
            f = e
            e = (d + T1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xffffffff
            
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff
        
    new_signature = (h0).to_bytes(4, byteorder='big') + (h1).to_bytes(4, byteorder='big') + \
                    (h2).to_bytes(4, byteorder='big') + (h3).to_bytes(4, byteorder='big') + \
                    (h4).to_bytes(4, byteorder='big') + (h5).to_bytes(4, byteorder='big') + \
                    (h6).to_bytes(4, byteorder='big') + (h7).to_bytes(4, byteorder='big')
    
    # new_data   = original_data + old_padded[secret_length + len(original_data):] + append_data
    old_padded = get_padding(length)
    new_data = original_data + old_padded + append_data
    return new_signature.hex(), new_data

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({"status": "OK"})

@app.route('/api/crypto/lea', methods=['POST'])
def process_lea():
    try:
        if not request.is_json:
            return jsonify({'error': '請求必須是 JSON 格式'}), 400
        
        data = request.get_json() 
        signature = data.get('signature')
        original_data = data.get('originalData')
        secret_length = data.get('secretLength')
        append_data = data.get('appendData')
        
        if not all([signature, original_data, secret_length, append_data]):
            return jsonify({'error': '所有欄位都必須填寫'}), 400
        
        try:
            secret_length = int(secret_length)
        except ValueError:
            return jsonify({'error': 'secretLength 必須是整數'}), 400
        
        new_sig, new_data = LEA(signature, original_data, append_data, secret_length)
        
        if isinstance(new_data, bytes):
            new_data = new_data.decode('utf-8', errors='ignore')
            
        return jsonify({
            'result': f"{new_sig}\n{new_data}"
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run()
