from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import requests
import random
import os
import json
import base64

app = Flask(__name__)
node_id = int(os.getenv('NODE_ID'))
nodes_info = [
    {'id': 0, 'address': 'localhost:5000'},
    {'id': 1, 'address': 'localhost:5001'},
    {'id': 2, 'address': 'localhost:5002'},
    {'id': 3, 'address': 'localhost:5003'},
    {'id': 4, 'address': 'localhost:5004'}
]

# Generate a new encryption key

key = b'wtlG91FJ41dIwIbM-psu_K6Bi4xB2yxbwOsBOuxfOtw='
cipher_suite = Fernet(key)

base64_encoded_key = base64.b64encode(key).decode()
os.environ['DESTINATION_KEY'] = base64_encoded_key

def decrypt_message(cipher_suite, encrypted_message):

    decrypted_message = cipher_suite.decrypt(base64.b64decode(encrypted_message))
    message_str = decrypted_message.decode()
    return message_str

@app.route('/send', methods=['POST'])
def send_message():
    data = json.loads(request.data.decode())
    #message = data['message'].encode()
    encrypted_message_str = data['message']
    final_destination = data['final_destination']
    path = data.get('path', [])
    path.append(node_id)

    #encrypted_message = cipher_suite.encrypt(message)
    #encrypted_message_str = base64.b64encode(encrypted_message).decode()

    if len(path) > 1:
        print(f"Mensaje moviéndose de nodo {path[-2]} a nodo {path[-1]}")

    if node_id == final_destination and len(path) == len(nodes_info):

        # Decrypt the message
        #decrypted_message = cipher_suite.decrypt(base64.b64decode(encrypted_message_str))
        key = base64.b64decode(os.environ['DESTINATION_KEY'])
        cipher_suite_destination = Fernet(key)
        decrypted_message = cipher_suite_destination.decrypt(base64.b64decode(encrypted_message_str))
        message_str = decrypted_message.decode()
        print(f"Mensaje recibido en destino final {node_id}: {message_str}")

        # Print the decrypted message for confirmation
        print(f"Mensaje descifrado: {message_str}")
        
        return jsonify({'status': 'delivered', 'node': node_id, 'path': path}), 200

    remaining_nodes = [node for node in nodes_info if node['id'] not in path and node['id'] != final_destination]
    if not remaining_nodes and node_id != final_destination:
        remaining_nodes = [node for node in nodes_info if node['id'] == final_destination]

    next_node = random.choice(remaining_nodes)
    print(f"Nodo {node_id} enviando mensaje a nodo {next_node['id']}")
    response = requests.post(f"http://{next_node['address']}/send", json={'message': encrypted_message_str, 'final_destination': final_destination, 'path': path})
    return response.json(), response.status_code

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)