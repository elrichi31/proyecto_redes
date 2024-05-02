from flask import Flask, request, jsonify
import requests
import random
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

app = Flask(__name__)

def load_keys(id_):
    # Cargar clave privada
    with open(f'keys/private_key_{id_}.pem', 'rb') as f:
        private_key = load_pem_private_key(
            f.read(),
            password=None,
        )
    
    # Cargar clave pública
    with open(f'keys/public_key_{id_}.pem', 'rb') as f:
        public_key = load_pem_public_key(f.read())

    return private_key, public_key


def encrypt_message(public_key, message):

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, encrypted_message):
    plaintext = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


node_id = int(os.getenv('NODE_ID'))
nodes_info = [
    {'id': 0, 'address': 'localhost:5000'},
    {'id': 1, 'address': 'localhost:5001'},
    {'id': 2, 'address': 'localhost:5002'},
    {'id': 3, 'address': 'localhost:5003'},
    {'id': 4, 'address': 'localhost:5004'}
]

def new_node(path, final_destination):
    remaining_nodes = [node for node in nodes_info if node['id'] not in path]
    if not remaining_nodes:
        remaining_nodes = [node for node in nodes_info if node['id'] == final_destination]

    next_node = random.choice(remaining_nodes)
    print(f"Nodo {node_id} enviando mensaje a nodo {next_node['id']}")
    return next_node


keys = {id_: load_keys(id_) for id_ in range(5)}


import base64
@app.route('/send', methods=['POST'])
def send_message():
    data = request.get_json()
    message = data['message']
    path = data.get('path', [])
    
    print(f"Mensaje encriptado -----> {message}")

    final_destination = data['final_destination']
    path.append(node_id)

    if len(path) == 1:
        public_key = keys[final_destination][1]
        private_key = keys[final_destination][0]
        message_encode = str(message).encode()
        message_encript = encrypt_message(public_key, message_encode)
        message_encript_base64 =  base64.b64encode(message_encript).decode('utf-8')

        bytes = base64.b64decode(message_encript_base64)

        message_de = decrypt_message(private_key, bytes)

        next_node = new_node(path, final_destination)
        print(f"Mensaje encriptado -----> {message_encript_base64} type {type(message_encript_base64)}")
        print(f"Mesanje desincriptado ------> {message_de.decode('utf-8')}")
        response = requests.post(f"http://{next_node['address']}/send", json={'message': message_encript_base64, 'final_destination': final_destination, 'path': path})
        if response.status_code == 200:
            try:
                return response.json(), response.status_code
            except ValueError:
                print("Response is not in JSON format.")
                return {'error': 'Response is not in JSON format'}, 500
        else:
            return {'error': 'Failed to send message', 'status': response.status_code}, response.status_code


    if node_id == final_destination:
        private_key = keys[final_destination][0]
        print(f"Mensaje final en destino -----> {message}")
        message_encript_bytes = base64.b64decode(message)
        message_final_encode = private_key.decrypt(
            message_encript_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        message_final = message_final_encode.decode('utf-8')

        print(f"Mensaje recibido en destino final {node_id}: {message_final}")
        return jsonify({'status': 'delivered', 'node': node_id, 'path': path, 'message': message_final}), 200

    remaining_nodes = [node for node in nodes_info if node['id'] not in path]
    if not remaining_nodes:
        remaining_nodes = [node for node in nodes_info if node['id'] == final_destination]

    next_node = random.choice(remaining_nodes)
    print(f"Nodo {node_id} enviando mensaje a nodo {next_node['id']}")

    response = requests.post(f"http://{next_node['address']}/send", json={'message': message, 'final_destination': final_destination, 'path': path})

    if response.status_code == 200:
        try:
            return response.json(), response.status_code
        except ValueError:
            print("Response is not in JSON format.")
            return {'error': 'Response is not in JSON format'}, 500
    else:
        return {'error': 'Failed to send message', 'status': response.status_code}, response.status_code


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
