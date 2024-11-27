from flask import Flask, request, jsonify
from lea import LEA

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
    app.run(host="0.0.0.0", port=10000)
