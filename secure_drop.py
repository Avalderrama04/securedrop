import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

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
import hashlib
import random
import re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Network configuration constants
PORT = 5555                # Main TCP port for secure communications
BROADCAST_PORT = 5556      # UDP port for presence broadcasting
BUFFER_SIZE = 1024        # Standard chunk size for network operations
BROADCAST_INTERVAL = 10    # Frequency of presence announcements (seconds)
ONLINE_TIMEOUT = 30       # Time before marking contact as offline (seconds)

# Global variables
running = True
current_user = None
local_ip = None

# File transfer global variables
sequence_number = random.randint(100000, 999999)
shared_secret = "secure_drop_secret" 
def derive_key(secret):
    return hashlib.sha256(secret.encode()).digest()
def compute_sha256(data):
    return hashlib.sha256(data).hexdigest()

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Doesn't actually send data
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
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
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
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
    data = json.loads(encrypted_data)
    encrypted_key = base64.b64decode(data['encrypted_key'])
    iv = base64.b64decode(data['iv'])
    encrypted_message = base64.b64decode(data['encrypted_message'])
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode()

#Function to provide salting towards hashed passwords
def secure_password(password):
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))

#If the stored hash of the password matches the userinput, authenticate user
def authenticate(password, stored_hash):
    return crypt.crypt(password, stored_hash) == stored_hash

#Function to create a user if one not registered
def make_user(choice):
    #Password must be minimum length of 10 characters; mix of uppercase, lowercase, numbers, special characters
    def valid_password(password):
        if len(password) < 10:
            print("Password must be at least 10 characters long.")
            return False
        if not re.search(r'[A-Z]', password):
            print("Password must include at least one uppercase letter.")
            return False
        if not re.search(r'[a-z]', password):
            print("Password must include at least one lowercase letter.")
            return False
        if not re.search(r'\d', password):
            print("Password must include at least one number.")
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            print("Password must include at least one special character.")
            return False
        return True
    
    full_name = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    
    #Set up password. Error check to meet requirements, and confirmation matches password
    while True:
        password = getpass.getpass("Enter Password: ")
        confirm_password = getpass.getpass("Re-enter Password: ")
        
        if password != confirm_password:
            print("Passwords do not match. Try again.\n")
            continue
        
        if not valid_password(password):
            print("Please try again.\n")
            continue
        
        break
    
    print("Passwords Match.")
    private_key, public_key = generate_key_pair()
    
    user_data = {
        'full_name': full_name,
        'email': email,
        'password': secure_password(password), 
        'public_key': public_key,
        'private_key': private_key
    }
    
    #Append registered user to users.json
    users.append(user_data)
    with open(users_file, 'w') as f:
        json.dump(users, f, indent=4)
    
    print("User Registered.")


#Function to ensure that email address and password match to login
def login(users_file):
    while True: 
        email = input("Enter Email Address: ").strip()
        password = getpass.getpass("Enter Password: ") 
        if not password:
            print("Empty password")
            continue
        with open(users_file, 'r') as f:
            users_data = json.load(f)
        user_found = None
        for user in users_data:
            if user['email'] == email:
                user_found = user
                break
        if not user_found:
            print("Email not found, try again")
            continue
        if authenticate(password, user_found['password']):
            print("\n✓ Successfully authenticated!")
            print("Welcome to SecureDrop.")
            return user_found
        else:
            print("Email and Password Combination Invalid.")

def make_contact(contacts_file):
    """Add a new contact to contacts.json"""
    full_name = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    
    # Load existing contacts or create a new list
    contacts = []
    if contacts_file.exists():
        try:
            with open(contacts_file, 'r') as f:
                contacts = json.load(f)
        except json.JSONDecodeError:
            contacts = []
    
    for contact in contacts:
        if contact['email'] == email:
            print(f"Contact with email {email} already exists.")
            return
    
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
    
# Function to start the UDP broadcast service
def start_broadcast_service():
    """Start the UDP broadcast service to announce presence on the network"""
    global current_user, local_ip, running
    def broadcast_thread():
        #Broadcast socket setup
        broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # SO_REUSEPORT may not be available
        broadcast_socket.settimeout(1)
        print("Network service started. Broadcasting presence...")
        try:
            while running:
                try:
                    message = {
                        #storing user data to the contacts.json file
                        'type': 'announce',
                        'email': current_user['email'],
                        'timestamp': time.time(),
                        'ip': local_ip
                    }
                    message_json = json.dumps(message)
                    try:
                        broadcast_socket.sendto(message_json.encode(), ('<broadcast>', BROADCAST_PORT))
                    except Exception:
                        parts = local_ip.split('.')
                        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                        broadcast_socket.sendto(message_json.encode(), (subnet, BROADCAST_PORT))
                    attempt_direct_announcements()
                    time.sleep(BROADCAST_INTERVAL)
                except socket.error:
                    time.sleep(1)
                    continue
        except Exception as e:
            print(f"Broadcast error: {e}")
        finally:
            broadcast_socket.close()
    t = threading.Thread(target=broadcast_thread, daemon=True)
    t.start()
# Function to attempt direct announcements to known contacts
def attempt_direct_announcements():
    """Try to directly announce presence to known contacts"""
    global contacts_file
    if not contacts_file.exists():
        return
    try:
        with open(contacts_file, 'r') as f:
            contacts = json.load(f)
        for contact in contacts:
            if contact.get('ip_address'):
                direct_announce_to_contact(contact)
    except Exception:
        pass
# Function to send a direct announcement to a specific contact
def direct_announce_to_contact(contact):
    """Send a direct announcement to a specific contact"""
    global current_user, local_ip
    if not contact.get('ip_address'):
        return False
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        client.settimeout(3)
        client.connect((contact['ip_address'], PORT))
        message = {
            'type': 'direct_announce',
            'email': current_user['email'],
            'timestamp': time.time(),
            'ip': local_ip
        }
        client.send(json.dumps(message).encode())
        client.close()
        return True
    except Exception:
        return False
# Function to start the UDP listener service
# to listen for broadcasts from other users
def start_listener_service(contacts_file):
    """Listen for broadcasts from other users on the network"""
    global running
    def listener_thread():
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            listener_socket.bind(('', BROADCAST_PORT))
        except Exception as e:
            print(f"Listener error: {e}")
            return
        listener_socket.settimeout(1)
        while running:
            try:
                data, addr = listener_socket.recvfrom(BUFFER_SIZE)
                message = json.loads(data.decode())
                if message.get('email') == current_user['email']:
                    continue
                update_contact_status(contacts_file, message)
            except socket.timeout:
                continue
            except json.JSONDecodeError:
                continue
            except Exception:
                continue
        listener_socket.close()
    t = threading.Thread(target=listener_thread, daemon=True)
    t.start()
# Function to start the TCP mutual check service
def start_mutual_check_service(contacts_file):
    """Handle TCP connections for mutual contact verification"""
    global current_user, running
    def server_thread():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            server_socket.bind(('', PORT))
        except Exception as e:
            print(f"Mutual check server error: {e}")
            return
        server_socket.listen(5)
        server_socket.settimeout(1)
        while running:
            try:
                client, addr = server_socket.accept()
                threading.Thread(target=handle_mutual_check, args=(client, contacts_file), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                continue
        server_socket.close()
    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

# Function to handle mutual contact verification and file transfer requests
def handle_mutual_check(client_socket, contacts_file):
    """Handle mutual contact verification request and direct announcements and file transfer request"""
    global current_user, local_ip
    try:
        client_socket.settimeout(30)
        data = client_socket.recv(BUFFER_SIZE)
        message = json.loads(data.decode())
        if message.get('type') == 'mutual_check':
            requester_email = message.get('email')
            with open(contacts_file, 'r') as f:
                contacts = json.load(f)
            is_contact = False
            updated = False
            for i, contact in enumerate(contacts):
                if contact['email'] == requester_email:
                    is_contact = True
                    contacts[i]['last_seen'] = time.time()
                    contacts[i]['online'] = True
                    if message.get('ip'):
                        contacts[i]['ip_address'] = message.get('ip')
                    updated = True
                    break
            if updated:
                with open(contacts_file, 'w') as f:
                    json.dump(contacts, f, indent=4)
            response = {
                'type': 'mutual_response',
                'email': current_user['email'],
                'is_contact': is_contact,
                'ip': local_ip
            }
            client_socket.send(json.dumps(response).encode())
        elif message.get('type') == 'direct_announce':
            sender_email = message.get('email')
            if contacts_file.exists():
                with open(contacts_file, 'r') as f:
                    contacts = json.load(f)
                updated = False
                for i, contact in enumerate(contacts):
                    if contact['email'] == sender_email:
                        contacts[i]['last_seen'] = message.get('timestamp', time.time())
                        contacts[i]['online'] = True
                        contacts[i]['ip_address'] = message.get('ip')
                        updated = True
                        if not contacts[i]['mutual']:
                            verify_mutual_status(contacts[i], i, contacts)
                        break
                if updated:
                    with open(contacts_file, 'w') as f:
                        json.dump(contacts, f, indent=4)
        # Request for file transfer
        elif message.get('type') == 'file_transfer_request':
            contact_name = next(
                (c['full_name'] for c in json.load(open(contacts_file)) if c['email'] == message['sender']),
                message['sender']
            )
            
            # Separate input prompt for receiver's terminal
            print(f"\nContact '{contact_name} <{message['sender']}>' is sending file: {message['filename']}")
            print(f"(Hit Enter)")
            while True:
                choice = input("Accept transfer? (y/n): ").strip().lower()
                if choice in ['y', 'n']:
                    break
                # Error check loop if not y/n input
                print("Please enter 'y' or 'n'", flush=True)
            
            # Receiver denies (return) or accepts (continue)
            if choice == 'n':
                client_socket.send(b'deny')
                return       
            client_socket.send(b'accept')
            
            # Receive encrypted data through transferring in chunks for large files
            received_data = b''
            try:
                while len(received_data) < int(message['filesize']):
                    chunk = client_socket.recv(min(BUFFER_SIZE, int(message['filesize']) - len(received_data)))
                    if not chunk:
                        raise ConnectionError("Connection dropped during transfer")
                    received_data += chunk
            # Error check if failed to transfer full file
            except (socket.timeout, ConnectionError) as e:
                print(f"\nTransfer interrupted: {e}")
                return

            # Decrypt data using AES, unique initialization vector
            aes_key = derive_key(shared_secret)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(base64.b64decode(message['iv'])))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(received_data) + decryptor.finalize()

            # Uses SHA-256 hashed shared secret for symmetric encryption, verify integrity by hash comparison
            if compute_sha256(decrypted_data) != message['checksum']:
                print("File integrity check failed.")
                return

            # Get path in receiver to save file
            script_directory = os.path.dirname(os.path.abspath(__file__))
            save_path = os.path.join(script_directory, message['filename'])
            # After full verification of transfer, output success
            try:
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"File saved to {save_path}")
            # Error check if failed to save
            except Exception as e:
                print(f"Error saving file: {e}")
    except Exception:
        pass
    finally:
        client_socket.close()

# Function to update contact status based on received messages
def update_contact_status(contacts_file, message):
    """Update a contact's online status and IP address"""
    if not contacts_file.exists():
        return
    try:
        with open(contacts_file, 'r') as f:
            contacts = json.load(f)
        updated = False
        for i, contact in enumerate(contacts):
            if contact['email'] == message.get('email'):
                contacts[i]['last_seen'] = message.get('timestamp')
                contacts[i]['online'] = True
                contacts[i]['ip_address'] = message.get('ip')
                updated = True
                if not contact.get('mutual'):
                    verify_mutual_status(contacts[i], i, contacts)
                break
        if updated:
            with open(contacts_file, 'w') as f:
                json.dump(contacts, f, indent=4)
    except Exception:
        pass

# Function to verify if a contact has also added us
def verify_mutual_status(contact, contact_index, contacts):
    """Check if a contact has also added us"""
    global current_user
    if not contact.get('ip_address'):
        return False
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        client.settimeout(30)
        client.connect((contact['ip_address'], PORT))
        request = {
            'type': 'mutual_check',
            'email': current_user['email'],
            'ip': local_ip
        }
        client.send(json.dumps(request).encode())
        response = json.loads(client.recv(BUFFER_SIZE).decode())
        if response.get('type') == 'mutual_response' and response.get('is_contact'):
            contacts[contact_index]['mutual'] = True
            return True
        client.close()
    except Exception:
        pass
    return False

# Function to periodically monitor and check contacts' status
def start_contact_monitor(contacts_file):
    """Periodically check contacts' status"""
    global running
    def monitor_thread():
        while running:
            try:
                if contacts_file.exists():
                    with open(contacts_file, 'r') as f:
                        contacts = json.load(f)
                    current_time = time.time()
                    updated = False
                    for i, contact in enumerate(contacts):
                        if contact.get('last_seen') and (current_time - contact['last_seen'] > ONLINE_TIMEOUT):
                            contacts[i]['online'] = False
                            updated = True
                        if contact.get('online', False) and not contact.get('mutual', False):
                            if verify_mutual_status(contact, i, contacts):
                                updated = True
                    if updated:
                        with open(contacts_file, 'w') as f:
                            json.dump(contacts, f, indent=4)
            except Exception:
                pass
            time.sleep(10)
    t = threading.Thread(target=monitor_thread, daemon=True)
    t.start()

# Function to list all contacts and their status
def list_contacts(contacts_file):
    """List all contacts with their status and verify mutual connections"""
    if not contacts_file.exists():
        print("No contacts found.")
        return
    try:
        # Load contacts from file
        with open(contacts_file, 'r') as f:
            contacts = json.load(f)
        if not contacts:
            print("No contacts found.")
            return

        current_time = time.time()
        updated = False
        
        # First pass: Update online status and force verify mutual connections
        for i, contact in enumerate(contacts):
            # Update online status
            if contact.get('last_seen'):
                is_online = (current_time - contact['last_seen'] < ONLINE_TIMEOUT)
                if contact.get('online', False) != is_online:
                    contact['online'] = is_online
                    updated = True
            
            # Force verify mutual status for all contacts
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)  # Short timeout for quick verification
                if contact.get('ip_address'):
                    try:
                        sock.connect((contact.get('ip_address'), PORT))
                        # Send verification request
                        message = {
                            'type': 'mutual_check',
                            'email': current_user['email']
                        }
                        sock.send(json.dumps(message).encode())
                        # Wait for response
                        response = sock.recv(BUFFER_SIZE)
                        if response:
                            response_data = json.loads(response.decode())
                            if response_data.get('status') == 'verified':
                                contact['mutual'] = True
                                updated = True
                    except (socket.timeout, ConnectionRefusedError):
                        contact['mutual'] = False
                        updated = True
            finally:
                sock.close()
        
        # Display all contacts and their statuses
        print("\nAll Contacts:")
        print("-------------")
        print(f"{'Name':<20} {'Email':<30} {'Status':<10} {'Mutual':<8}")
        print("-" * 70)
        
        for contact in contacts:
            status = "Online" if contact.get('online', False) else "Offline"
            mutual = "Yes" if contact.get('mutual', False) else "No"
            print(f"{contact['full_name']:<20} {contact['email']:<30} {status:<10} {mutual:<8}")
        
        # Display only available for transfer contacts
        online_mutual = [c for c in contacts if c.get('online', False) and c.get('mutual', False)]
        if online_mutual:
            print("\nOnline Mutual Contacts (available for file transfer):")
            print("---------------------------------------------------")
            for i, contact in enumerate(online_mutual, 1):
                print(f"{i}. {contact['full_name']} ({contact['email']})")
        else:
            print("\nNo contacts are both online and mutual (required for file transfer).")
        
        # Save updates if needed
        if updated:
            with open(contacts_file, 'w') as f:
                json.dump(contacts, f, indent=4)
                
    except Exception as e:
        print(f"Error listing contacts: {e}")
# Function to display available commands in help function
def print_help():
    """Display available commands"""
    print("\nAvailable Commands:")
    print("------------------")
    print("  add    -> Add a new contact")
    print("  list   -> List all contacts and statuses")
    print("  send   -> Transfer file to contact (usage: send <email> <file_path>)")
    print("  help   -> Show these commands")
    print("  exit   -> Exit SecureDrop\n")

def send_file_to_contact(recipient_email, file_path, current_user, contacts_file):
    """Milestone 5: transfers a file securely to a contact"""
    global sequence_number
    # Error check if file does not exist
    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    with open(contacts_file, 'r') as f:
        contacts = json.load(f)
    # Error check if recipient is not mutual, online, and valid IP
    contact = next((c for c in contacts if c['email'] == recipient_email), None)
    if not contact or not contact.get('online') or not contact.get('mutual') or not contact.get('ip_address'):
        print("Contact must be mutual, online, and have a valid IP.")
        return

    # Read and hash file. Set up encryption
    with open(file_path, 'rb') as f:
        file_data = f.read()
    checksum = compute_sha256(file_data) # pre-transfer hash
    aes_key = derive_key(shared_secret) # shared secret key
    iv = os.urandom(16) # unique iv for a transfer
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    try:
        # Connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((contact['ip_address'], PORT))

        # Send metadata to recipient
        metadata = {
            'type': 'file_transfer_request',
            'filename': os.path.basename(file_path),
            'filesize': len(encrypted_data),
            'iv': base64.b64encode(iv).decode(),         # Initialization Vector for AES
            'sender': current_user['email'],
            'checksum': checksum,                        # SHA-256 hash for integrity
            'sequence_number': sequence_number           # Anti-replay protection
        }
        sock.send(json.dumps(metadata).encode())
        # Recipient handling occurs in handle_mutual_check
        
        # Wait for recipient to accept or deny
        response = sock.recv(BUFFER_SIZE).decode().strip().lower()
        # Error check for deny
        if response != 'accept':
            print("Contact has declined the transfer request.")
            return
        print("Contact has accepted the transfer request.")
        sock.sendall(encrypted_data)
        print("File has been successfully transferred.")
        
        # Prevent replay attacks with sequence numbers updated each transfer request
        sequence_number += 1
    except Exception as e:
        print(f"Error sending file: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    users_file = Path('users.json')
    contacts_file = Path('contacts.json')
    users = []
    
    local_ip = get_local_ip()
    
    #If no users registered with client, prompt to register a new user
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
        else:
            print("Exiting SecureDrop.")
            sys.exit(0)
    
    current_user = login(users_file)
    
    if not contacts_file.exists():
        with open(contacts_file, 'w') as f:
            json.dump([], f, indent=4)
    
    print("Starting network services...")
    start_broadcast_service()
    start_listener_service(contacts_file)
    start_mutual_check_service(contacts_file)
    start_contact_monitor(contacts_file)
    
    print("Type \"help\" for commands.")

    #Handle user commands in securedrop with exceptions
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
            elif command.startswith('send'):
                try:
                    parts = command.split()
                    if len(parts) != 3:
                        print("Usage: send <recipientemail> <filepath>")
                        continue
                    email = parts[1]
                    path = parts[2]
                    send_file_to_contact(email, path, current_user, contacts_file)
                except Exception as e:
                    print(f"Error: {e}")
            elif command == "":
                continue
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for a list of commands.")
    except KeyboardInterrupt:
        running = False
        print("\nExiting SecureDrop. Goodbye!")
        sys.exit(0)