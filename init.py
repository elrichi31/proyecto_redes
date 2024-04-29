from flask import Flask, request, jsonify
import requests
import random
import os
from cryptography.fernet import Fernet

app = Flask(__name__)
node_id = int(os.getenv('NODE_ID'))
nodes_info = [
    {'id': 0, 'address': 'localhost:5000'},
    {'id': 1, 'address': 'localhost:5001'},
    {'id': 2, 'address': 'localhost:5002'},
    {'id': 3, 'address': 'localhost:5003'},
    {'id': 4, 'address': 'localhost:5004'}
]

# Clave de encriptación
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_message(message):
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message).decode()

import json

@app.route('/send', methods=['POST'])
def send_message():
    data = request.get_json()
    message = data['message']
    final_destination = data['final_destination']
    path = data.get('path', [])
    path.append(node_id)

    # Encriptar el mensaje antes de enviarlo
    encrypted_message = encrypt_message(message)

    if len(path) > 1:
        print(f"Mensaje encriptado moviéndose de nodo {path[-2]} a nodo {path[-1]}")

    if node_id == final_destination and len(path) == len(nodes_info):
        # Desencriptar el mensaje al llegar al destino final
        decrypted_message = decrypt_message(encrypted_message)
        print(f"Mensaje recibido en destino final {node_id}: {decrypted_message}")
        return jsonify({'status': 'delivered', 'node': node_id, 'path': path, 'message': decrypted_message}), 200

    remaining_nodes = [node for node in nodes_info if node['id'] not in path and node['id'] != final_destination]
    if not remaining_nodes and node_id != final_destination:
        remaining_nodes = [node for node in nodes_info if node['id'] == final_destination]

    next_node = random.choice(remaining_nodes)
    print(f"Nodo {node_id} enviando mensaje encriptado a nodo {next_node['id']}")

    # Crear el objeto JSON correctamente formateado
    payload = {
        'message': encrypted_message.decode(), 
        'final_destination': final_destination, 
        'path': path
    }
    
    # Enviar la solicitud con el objeto JSON como datos
    headers = {'Content-Type': 'application/json'}
    response = requests.post(f"http://{next_node['address']}/send", data=json.dumps(payload), headers=headers)

    # Devolver el texto de la respuesta sin intentar interpretarlo como JSON
    return response.text, response.status_code




if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
