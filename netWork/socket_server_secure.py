import socket
import json
import ssl
from pymongo import MongoClient
import hashlib
from collections import defaultdict
import time

# # Argon2 setup
# ph = PasswordHasher()
# MongoDB setup (default port 27017)'
mongo_client = MongoClient('mongodb://localhost:27017/')
db = mongo_client['network_security_db']
users_collection = db['users']

# Rate limiting setup
MAX_ATTEMPTS = 5  # Max 5 attempts per minute
attempts = defaultdict(list)  # Tracks attempts by client IP

def check_rate_limit(client_addr):
    """Check if the client has exceeded the rate limit."""
    current_time = time.time()
    client_ip = client_addr[0]
    
    # Clean up attempts older than 60 seconds
    attempts[client_ip] = [t for t in attempts[client_ip] if current_time - t < 60]
    
    # Check if limit exceeded
    if len(attempts[client_ip]) >= MAX_ATTEMPTS:
        return False
    
    # Record this attempt
    attempts[client_ip].append(current_time)
    return True

def start_socket_server():
    # Create a basic socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to localhost:9999
    server_socket.bind(('localhost', 9999))
    
    # TLS/SSL setup
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="netWork/server.crt", keyfile="netWork/server.key")  # Adjust path if needed
    server_socket = context.wrap_socket(server_socket, server_side=True)
    
    # Listen for connections
    server_socket.listen(1)
    print("Socket server started on port 9999 with TLS")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        data = client_socket.recv(1024).decode()
        if not data:
            client_socket.close()
            continue
        
        try:
            # Check rate limit
            if not check_rate_limit(addr):
                response = "Rate limit exceeded! Try again in a minute."
                client_socket.send(response.encode())
                client_socket.close()
                continue

            # Parse the client request
            request = json.loads(data)
            action = request["action"]
            username = request["username"]

            if action == "register":
                if users_collection.find_one({"username": username}):
                    response = "Username already exists!"
                else:
                    # Use the pre-hashed password and salt from the client
                    hashed_password = request["password_hash"]
                    salt = request["salt"]
                    user_data = {
                        "username": username,
                        "password_hash": hashed_password,
                        "salt": salt
                    }
                    users_collection.insert_one(user_data)
                    response = "Registration successful!"
            
            elif action == "login":
                user = users_collection.find_one({"username": username})
                if user:
                    stored_hash = user["password_hash"]
                    stored_salt = user["salt"]
                    # Hash the received plaintext password with SHA-256 and stored salt
                    hashed_input = hashlib.sha256((request["password"] + stored_salt).encode()).hexdigest()
                    if hashed_input == stored_hash:
                        response = "Login successful!"
                    else:
                        response = "Invalid credentials!"
                else:
                    response = "User not found!"

            # Send response (TLS encrypts it)
            client_socket.send(response.encode())
        
        except Exception as e:
            print(f"Error: {e}")
            client_socket.send("An error occurred!".encode())
        
        finally:
            client_socket.close()

if __name__ == "__main__":
    start_socket_server()