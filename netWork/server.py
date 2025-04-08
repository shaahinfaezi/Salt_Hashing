import socket
import json
from pymongo import MongoClient
import hashlib

# MongoDB setup (default port 27017)
mongo_client = MongoClient('mongodb://localhost:27017/')
db = mongo_client['network_security_db_insecure']
users_collection = db['users']

def hash_password(password):
    """Hash the password using SHA-256 without salt."""
    return hashlib.sha256(password.encode()).hexdigest()

def start_socket_server():
    # Create a basic socket (no TLS)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to localhost:9999
    server_socket.bind(('localhost', 9999))
    
    # Listen for connections
    server_socket.listen(1)
    print("Socket server started on port 9999 (No TLS)")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        data = client_socket.recv(1024).decode()
        if not data:
            client_socket.close()
            continue
        
        try:
            # Parse the client request
            request = json.loads(data)
            action = request["action"]
            username = request["username"]

            if action == "register":
                if users_collection.find_one({"username": username}):
                    response = "Username already exists!"
                else:
                    hashed_password = request["password_hash"]  # Use pre-hashed password from client
                    user_data = {
                        "username": username,
                        "password_hash": hashed_password
                    }
                    users_collection.insert_one(user_data)
                    response = "Registration successful!"
            
            elif action == "login":
                user = users_collection.find_one({"username": username})
                if user:
                    stored_hash = user["password_hash"]
                    # Hash the received plaintext password and compare
                    if hash_password(request["password"]) == stored_hash:
                        response = "Login successful!"
                    else:
                        response = "Invalid credentials!"
                else:
                    response = "User not found!"

            # Send response (plaintext, no TLS)
            client_socket.send(response.encode())
        
        except Exception as e:
            print(f"Error: {e}")
            client_socket.send("An error occurred!".encode())
        
        finally:
            client_socket.close()

if __name__ == "__main__":
    start_socket_server()