import json
import sys
import getpass
import socket
import threading
import time
from pathlib import Path
import crypt
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Network configuration
PORT = 5555
BROADCAST_PORT = 5556
BUFFER_SIZE = 1024
BROADCAST_INTERVAL = 10  # seconds
ONLINE_TIMEOUT = 30  # seconds - how long before considering a contact offline

# Global variables
running = True
current_user = None
local_ip = None

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Doesn't actually send data
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        # Fallback if we can't determine IP
        return "127.0.0.1"

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_pem, public_pem

def encrypt_message(message, public_key_str):
    """Encrypt a message using the recipient's public key"""
    public_key = serialization.load_pem_public_key(public_key_str.encode())
    
    # Generate a random AES key
    aes_key = os.urandom(32)  # 256-bit key
    
    # Encrypt the message with AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    
    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Combine everything
    result = {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'iv': base64.b64encode(iv).decode(),
        'encrypted_message': base64.b64encode(encrypted_message).decode()
    }
    
    return json.dumps(result)

def decrypt_message(encrypted_data, private_key_str):
    """Decrypt a message using your private key"""
    private_key = serialization.load_pem_private_key(
        private_key_str.encode(),
        password=None
    )
    
    # Parse the encrypted data
    data = json.loads(encrypted_data)
    encrypted_key = base64.b64decode(data['encrypted_key'])
    iv = base64.b64decode(data['iv'])
    encrypted_message = base64.b64decode(data['encrypted_message'])
    
    # Decrypt the AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    return decrypted_message.decode()

def secure_password(password):
    hash = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    return hash 

def authenticate(password, hash):
    return crypt.crypt(password, hash) == hash

def make_user(choice):
    full_name = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    password = getpass.getpass("Enter Password: ")
    confirm_password = getpass.getpass("Re-enter Password: ")
    
    if password != confirm_password:
        print("Passwords do not match. Exiting.")
        sys.exit(1)
    
    print("Passwords Match.")

    private_key, public_key = generate_key_pair()
    
    user_data = {
        'full_name': full_name,
        'email': email,
        'password': secure_password(password), 
        'public_key': public_key,
        'private_key': private_key
    }
    
    users.append(user_data)
    with open(users_file, 'w') as f:
        json.dump(users, f, indent=4)
    
    print("User Registered.")

def login(users_file):
    while True: 
        email = input("Enter Email Address: ").strip()
        password = getpass.getpass("Enter Password: ") 
        if len(password) == 0:
            print("Empty password")
            password = getpass.getpass("Enter Password: ") 
                    
        with open(users_file, 'r') as f:
            users = json.load(f)
            
        email_success = None
        for user in users:
            if user['email'] == email:
                email_success = user
                break
                
        if not email_success:
            print("Email not found, try again")
            continue
            
        if authenticate(password, email_success['password']):
            print("\n✓ Successfully authenticated!")
            print("Welcome to SecureDrop.")
            return email_success
        else: 
            print("Email and Password Combination Invalid.")
            continue
                            
def make_contact(contacts_file):
    """Add a new contact to contacts.json"""
    full_name = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    
    # Load existing contacts or create new contacts list
    contacts = []
    if contacts_file.exists():
        try:
            with open(contacts_file, 'r') as f:
                contacts = json.load(f)
        except json.JSONDecodeError:
            contacts = []
    
    # Check if contact already exists
    for contact in contacts:
        if contact['email'] == email:
            print(f"Contact with email {email} already exists.")
            return
    
    # Add new contact with network properties
    contact_data = {
        'full_name': full_name,
        'email': email,
        'mutual': False,
        'online': False,
        'ip_address': None,
        'last_seen': None
    }
    
    contacts.append(contact_data)
    with open(contacts_file, 'w') as f:
        json.dump(contacts, f, indent=4)
    
    print(f"Contact {full_name} added successfully.")

def start_broadcast_service():
    """Start the UDP broadcast service to announce presence on the network"""
    global current_user, local_ip, running
    
    def broadcast_thread():
        # Create broadcast socket
        broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Set socket timeout to prevent blocking issues
        broadcast_socket.settimeout(1)
        
        print("Network service started. Broadcasting presence...")
        
        try:
            while running:
                try:
                    # Prepare message with user info
                    message = {
                        'type': 'announce',
                        'email': current_user['email'],
                        'timestamp': time.time(),
                        'ip': local_ip
                    }
                    
                    # Sign message with private key (simplified for now)
                    message_json = json.dumps(message)
                    
                    # Broadcast to local network
                    try:
                        broadcast_socket.sendto(message_json.encode(), ('<broadcast>', BROADCAST_PORT))
                    except:
                        # Fallback to subnet broadcast if direct broadcast fails
                        parts = local_ip.split('.')
                        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                        broadcast_socket.sendto(message_json.encode(), (subnet, BROADCAST_PORT))
                        
                    time.sleep(BROADCAST_INTERVAL)
                except socket.error:
                    time.sleep(1)
                    continue
                    
        except Exception as e:
            print(f"Broadcast error: {e}")
        finally:
            broadcast_socket.close()
    
    # Start broadcast in background thread
    broadcast_thread = threading.Thread(target=broadcast_thread)
    broadcast_thread.daemon = True
    broadcast_thread.start()

def start_listener_service(contacts_file):
    """Listen for broadcasts from other users on the network"""
    global running
    
    def listener_thread():
        # Create listener socket
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to broadcast port
        try:
            listener_socket.bind(('', BROADCAST_PORT))
            # Set timeout to prevent blocking issues
            listener_socket.settimeout(1)
            
            while running:
                try:
                    # Receive announcement
                    data, addr = listener_socket.recvfrom(BUFFER_SIZE)
                    message = json.loads(data.decode())
                    
                    # Skip our own messages
                    if message.get('email') == current_user['email']:
                        continue
                    
                    # Update contact if in our list
                    update_contact_status(contacts_file, message)
                    
                except socket.timeout:
                    continue
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"Listener error: {e}")
        finally:
            listener_socket.close()
    
    # Start listener in background thread
    listener_thread = threading.Thread(target=listener_thread)
    listener_thread.daemon = True
    listener_thread.start()

def start_mutual_check_service(contacts_file):
    """Handle TCP connections for mutual contact verification"""
    global current_user, running
    
    def server_thread():
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(('', PORT))
            server_socket.listen(5)
            server_socket.settimeout(1)
            
            while running:
                try:
                    # Accept connection
                    client, addr = server_socket.accept()
                    
                    # Handle in separate thread
                    threading.Thread(target=handle_mutual_check, args=(client, contacts_file), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    continue
        except Exception as e:
            print(f"Mutual check server error: {e}")
        finally:
            server_socket.close()
    
    # Start server in background thread
    server_thread = threading.Thread(target=server_thread)
    server_thread.daemon = True
    server_thread.start()

def handle_mutual_check(client_socket, contacts_file):
    """Handle mutual contact verification request"""
    global current_user
    
    try:
        # Set timeout to prevent hanging
        client_socket.settimeout(5)
        
        # Receive request
        data = client_socket.recv(BUFFER_SIZE)
        message = json.loads(data.decode())
        
        if message.get('type') == 'mutual_check':
            requester_email = message.get('email')
            
            # Check if we have this contact
            with open(contacts_file, 'r') as f:
                contacts = json.load(f)
            
            # See if we have the requester in our contacts
            is_contact = False
            for contact in contacts:
                if contact['email'] == requester_email:
                    is_contact = True
                    break
            
            # Send response
            response = {
                'type': 'mutual_response',
                'email': current_user['email'],
                'is_contact': is_contact
            }
            
            client_socket.send(json.dumps(response).encode())
    except Exception as e:
        pass
    finally:
        client_socket.close()

def update_contact_status(contacts_file, message):
    """Update a contact's online status and IP address"""
    if not contacts_file.exists():
        return
    
    try:
        # Load contacts
        with open(contacts_file, 'r') as f:
            contacts = json.load(f)
        
        updated = False
        for i, contact in enumerate(contacts):
            if contact['email'] == message.get('email'):
                # Update contact info
                contacts[i]['last_seen'] = message.get('timestamp')
                contacts[i]['online'] = True
                contacts[i]['ip_address'] = message.get('ip')
                updated = True
                
                # Check for mutual status if not already verified
                if not contacts[i]['mutual']:
                    verify_mutual_status(contacts[i], i, contacts)
                
                break
        
        if updated:
            # Save updated contacts
            with open(contacts_file, 'w') as f:
                json.dump(contacts, f, indent=4)
    except Exception as e:
        pass

def verify_mutual_status(contact, contact_index, contacts):
    """Check if a contact has also added us"""
    global current_user
    
    if not contact.get('ip_address'):
        return
    
    try:
        # Create client socket
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        
        # Connect to contact
        client.connect((contact['ip_address'], PORT))
        
        # Send mutual check request
        request = {
            'type': 'mutual_check',
            'email': current_user['email']
        }
        
        client.send(json.dumps(request).encode())
        
        # Get response
        response = json.loads(client.recv(BUFFER_SIZE).decode())
        
        if response.get('type') == 'mutual_response' and response.get('is_contact'):
            # They have us in their contacts too
            contacts[contact_index]['mutual'] = True
        
        client.close()
    except Exception as e:
        pass

def list_contacts(contacts_file):
    """List all contacts that are online and mutual"""
    if not contacts_file.exists():
        print("No contacts found.")
        return
    
    try:
        # Load contacts
        with open(contacts_file, 'r') as f:
            contacts = json.load(f)
        
        if not contacts:
            print("No contacts found.")
            return
        
        # Check which contacts are still online based on last_seen timestamp
        current_time = time.time()
        online_mutual_contacts = []
        
        for contact in contacts:
            # Check if last seen within timeout period
            if contact.get('last_seen') and (current_time - contact['last_seen'] < ONLINE_TIMEOUT):
                contact['online'] = True
                
                # Only show contacts that are both online and mutual
                if contact.get('mutual', False):
                    online_mutual_contacts.append(contact)
            else:
                contact['online'] = False
        
        # Save updated online status
        with open(contacts_file, 'w') as f:
            json.dump(contacts, f, indent=4)
        
        # Display online mutual contacts
        if not online_mutual_contacts:
            print("No online mutual contacts found.")
            return
        
        print("\nOnline Contacts:")
        print("---------------")
        for i, contact in enumerate(online_mutual_contacts, 1):
            print(f"{i}. {contact['full_name']} ({contact['email']})")
        print()
    except Exception as e:
        print(f"Error listing contacts: {e}")

def print_help():
    """Display available commands"""
    print("\nAvailable Commands:")
    print("------------------")
    print("  add   -> Add a new contact")
    print("  list  -> List all online contacts")
    print("  send  -> Transfer file to contact")
    print("  help  -> Show these commands")
    print("  exit  -> Exit SecureDrop")
    print()

if __name__ == "__main__":
    users_file = Path('users.json')
    contacts_file = Path('contacts.json')
    users = []
    
    # Get local IP address
    local_ip = get_local_ip()
    
    if users_file.exists(): 
        with open(users_file, 'r') as f:
            users = json.load(f)
    else:
        print("No users are registered with this client.")
        choice = input("Do you want to register a new user (y/n)? ").strip().lower()
        if choice == 'y':
            make_user(choice)
            print("Exiting SecureDrop.")
            sys.exit(0)

        if choice == 'n':
            print("Exiting SecureDrop.")
            sys.exit(0)
    
    # Login user
    current_user = login(users_file)
    
    # Initialize or create contacts file if it doesn't exist
    if not contacts_file.exists():
        with open(contacts_file, 'w') as f:
            json.dump([], f, indent=4)
    
    # Start network services
    print("Starting network services...")
    start_broadcast_service()
    start_listener_service(contacts_file)
    start_mutual_check_service(contacts_file)
    
    print("Type \"help\" For Commands.")
    
    try:
        while True:
            command = input("\nSecureDrop> ").strip().lower()
            if command == 'exit':
                running = False
                print("Exiting SecureDrop. Goodbye!")
                sys.exit(0)
            elif command == 'add':
                make_contact(contacts_file)
            elif command == 'list':
                list_contacts(contacts_file)
            elif command == 'help':
                print_help()
            elif command == 'send':
                print("Send feature not yet implemented.")
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for a list of commands.")
    except KeyboardInterrupt:
        running = False
        print("\nExiting SecureDrop. Goodbye!")
        sys.exit(0)