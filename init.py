from flask import Flask, request, jsonify
import requests
import random
import os

app = Flask(__name__)
node_id = int(os.getenv('NODE_ID'))
nodes_info = [
    {'id': 0, 'address': 'localhost:5000'},
    {'id': 1, 'address': 'localhost:5001'},
    {'id': 2, 'address': 'localhost:5002'},
    {'id': 3, 'address': 'localhost:5003'},
    {'id': 4, 'address': 'localhost:5004'}
]

@app.route('/send', methods=['POST'])
def send_message():
    data = request.get_json()
    message = data['message']
    final_destination = data['final_destination']
    path = data.get('path', [])
    path.append(node_id)

    if len(path) > 1:
        print(f"Mensaje moviéndose de nodo {path[-2]} a nodo {path[-1]}")

    if node_id == final_destination and len(path) == len(nodes_info):
        print(f"Mensaje recibido en destino final {node_id}: {message}")
        return jsonify({'status': 'delivered', 'node': node_id, 'path': path}), 200

    remaining_nodes = [node for node in nodes_info if node['id'] not in path and node['id'] != final_destination]
    if not remaining_nodes and node_id != final_destination:
        remaining_nodes = [node for node in nodes_info if node['id'] == final_destination]

    next_node = random.choice(remaining_nodes)
    print(f"Nodo {node_id} enviando mensaje a nodo {next_node['id']}")
    response = requests.post(f"http://{next_node['address']}/send", json={'message': message, 'final_destination': final_destination, 'path': path})
    return response.json(), response.status_code

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
