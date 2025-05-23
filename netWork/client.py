import socket
import json
import tkinter as tk
from tkinter import messagebox, ttk
import hashlib

def hash_password(password):
    """Hash the password using SHA-256 without salt."""
    return hashlib.sha256(password.encode()).hexdigest()

def send_request(action, username, password):
    """Send a request to the server and return the response."""
    try:
        # Create a basic socket (no TLS)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to the server
        client_socket.connect(('localhost', 9999))
        
        # Prepare the request
        if action == "register":
            hashed_password = hash_password(password)
            request = {
                "action": action,
                "username": username,
                "password_hash": hashed_password  # Send hashed password
            }
        elif action == "login":
            request = {
                "action": action,
                "username": username,
                "password": password  # Send plaintext password for login
            }
        
        # Send the request
        client_socket.send(json.dumps(request).encode())
        
        # Receive the response
        response = client_socket.recv(1024).decode()
        
        return response
    except Exception as e:
        return f"Error: {e}"
    finally:
        client_socket.close()

def register():
    """Handle registration."""
    username = entry_username.get()
    password = entry_password.get()
    
    if not username or not password:
        messagebox.showerror("Error", "Please enter both username and password")
        return
    
    response = send_request("register", username, password)
    messagebox.showinfo("Result", response)

def login():
    """Handle login."""
    username = entry_username.get()
    password = entry_password.get()
    
    if not username or not password:
        messagebox.showerror("Error", "Please enter both username and password")
        return
    
    response = send_request("login", username, password)
    messagebox.showinfo("Result", response)

# Enhanced Tkinter GUI setup
root = tk.Tk()
root.title("Login & Registration (No TLS)")
root.geometry("450x350")
root.configure(bg="#e0e7ff")  # Soft purple-blue background

# Style configuration
style = ttk.Style()
style.theme_use("clam")  # Modern theme
style.configure("TLabel", font=("Arial", 14), background="#e0e7ff", foreground="#333333")
style.configure("TEntry", font=("Arial", 12))
style.configure("TButton", font=("Arial", 12, "bold"), padding=10)

# Frame for content with a subtle border
frame = ttk.Frame(root, padding="30", relief="flat", borderwidth=2, style="Custom.TFrame")
frame.pack(expand=True)

# Custom frame style for a slight shadow effect
style.configure("Custom.TFrame", background="#ffffff", bordercolor="#d1d8e0")

# Title
title_label = ttk.Label(frame, text="Welcome!", font=("Arial", 20, "bold"), foreground="#4a69bd")
title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

# Labels and Entries with styling
ttk.Label(frame, text="Username").grid(row=1, column=0, pady=10, sticky="e")
entry_username = ttk.Entry(frame, width=25, font=("Arial", 12))
entry_username.grid(row=1, column=1, pady=10)

ttk.Label(frame, text="Password").grid(row=2, column=0, pady=10, sticky="e")
entry_password = ttk.Entry(frame, width=25, show="*", font=("Arial", 12))
entry_password.grid(row=2, column=1, pady=10)

# Buttons with gradient-like colors and hover effects
btn_register = ttk.Button(frame, text="Register", command=register, style="Accent.TButton")
btn_register.grid(row=3, column=0, pady=20, padx=10)

btn_login = ttk.Button(frame, text="Login", command=login, style="Accent.TButton")
btn_login.grid(row=3, column=1, pady=20, padx=10)

# Custom button style
style.configure("Accent.TButton", background="#6b7280", foreground="white", borderwidth=0)
style.map("Accent.TButton", 
          background=[("active", "#4b5563"), ("pressed", "#374151")],  # Darker shades on hover/click
          foreground=[("active", "white")])

# Center the frame
frame.place(relx=0.5, rely=0.5, anchor="center")

# Start the GUI
root.mainloop()