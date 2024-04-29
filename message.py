from cryptography.fernet import Fernet
import base64

# Generate a key or use a fixed key that matches the one used in your Flask app
key = b'wtlG91FJ41dIwIbM-psu_K6Bi4xB2yxbwOsBOuxfOtw='  # For real testing, ensure this key matches across all your Flask nodes
cipher_suite = Fernet(key)

# Prepare a test message
message = "Hello, this is a test message."
encrypted_message = cipher_suite.encrypt(message.encode())
encoded_message = base64.urlsafe_b64encode(encrypted_message).decode()

# Output the encoded message to be used in POST requests
print(encoded_message)