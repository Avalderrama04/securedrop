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
import struct
import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Network configuration
PORT = 5555
BROADCAST_PORT = 5556
BUFFER_SIZE = 1024
BROADCAST_INTERVAL = 10  # seconds
ONLINE_TIMEOUT = 30      # seconds - how long before considering a contact offline

FILE_TRANSFER_DIR = "received_files"  # Directory to store received files
SEQUENCE_NUM = random.randint(0, 2**32 - 1)  # Random initial sequence number

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

def secure_password(password):
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))

def authenticate(password, stored_hash):
    return crypt.crypt(password, stored_hash) == stored_hash

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

def start_broadcast_service():
    """Start the UDP broadcast service to announce presence on the network"""
    global current_user, local_ip, running
    def broadcast_thread():
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

def handle_mutual_check(client_socket, contacts_file):
    """Handle mutual contact verification request and direct announcements and file transfer request"""
    global current_user, local_ip
    try:
        client_socket.settimeout(30)
        data = client_socket.recv(BUFFER_SIZE)
        message = json.loads(data.decode())
        
        if message.get('type') == 'file_transfer_request':
            print(f"\nIncoming file transfer request detected from {message.get('from_email')}")
            handle_file_transfer_request(client_socket, contacts_file)
            return
        elif message.get('type') == 'mutual_check':
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
    except Exception:
        pass
    finally:
        client_socket.close()

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

def list_contacts(contacts_file):
    """List all contacts with their status"""
    if not contacts_file.exists():
        print("No contacts found.")
        return
    try:
        with open(contacts_file, 'r') as f:
            contacts = json.load(f)
        if not contacts:
            print("No contacts found.")
            return
        current_time = time.time()
        updated = False
        print("\nAll Contacts:")
        print("-------------")
        print(f"{'Name':<20} {'Email':<30} {'Status':<10} {'Mutual':<8}")
        print("-" * 70)
        for i, contact in enumerate(contacts):
            if contact.get('last_seen') and (current_time - contact['last_seen'] < ONLINE_TIMEOUT):
                if not contact.get('online', False):
                    contact['online'] = True
                    updated = True
            else:
                if contact.get('online', False):
                    contact['online'] = False
                    updated = True
            status = "Online" if contact.get('online', False) else "Offline"
            mutual = "Yes" if contact.get('mutual', False) else "No"
            print(f"{contact['full_name']:<20} {contact['email']:<30} {status:<10} {mutual:<8}")
        online_mutual = [c for c in contacts if c.get('online', False) and c.get('mutual', False)]
        if online_mutual:
            print("\nOnline Mutual Contacts (available for file transfer):")
            print("---------------------------------------------------")
            for i, contact in enumerate(online_mutual, 1):
                print(f"{i}. {contact['full_name']} ({contact['email']})")
        else:
            print("\nNo contacts are both online and mutual (required for file transfer).")
        if updated:
            with open(contacts_file, 'w') as f:
                json.dump(contacts, f, indent=4)
    except Exception as e:
        print(f"Error listing contacts: {e}")

def print_help():
    """Display available commands"""
    print("\nAvailable Commands:")
    print("------------------")
    print("  add    -> Add a new contact")
    print("  list   -> List all contacts and statuses")
    print("  verify -> Force mutual verification for all contacts")
    print("  send   -> Transfer file to contact (usage: send <email> <file_path>)")
    print("  help   -> Show these commands")
    print("  exit   -> Exit SecureDrop\n")

def force_mutual_check(contacts_file):
    """Force a mutual check for all contacts"""
    if not contacts_file.exists():
        print("No contacts found.")
        return
    try:
        with open(contacts_file, 'r') as f:
            contacts = json.load(f)
        if not contacts:
            print("No contacts found.")
            return
        print("Checking mutual status for all contacts...")
        for i, contact in enumerate(contacts):
            if verify_mutual_status(contact, i, contacts):
                print(f"✓ Mutual verification successful for {contact['full_name']}")
        with open(contacts_file, 'w') as f:
            json.dump(contacts, f, indent=4)
        print("Mutual verification completed.")
    except Exception as e:
        print(f"Error checking mutual status: {e}")
        
def send_file(contact_email, file_path):
    """Send a file to a contact"""
    global current_user, contacts_file, SEQUENCE_NUM
    
    # Check if contact exists and is mutual
    if not contacts_file.exists():
        print("No contacts found.")
        return
    
    with open(contacts_file, 'r') as f:
        contacts = json.load(f)
    
    contact = None
    for c in contacts:
        if c['email'] == contact_email:
            contact = c
            break
    
    if not contact:
        print(f"Contact with email {contact_email} not found.")
        return
    
    if not contact.get('mutual', False):
        print(f"Contact {contact['full_name']} is not a mutual contact.")
        return
    
    if not contact.get('online', False):
        print(f"Contact {contact['full_name']} is offline.")
        return
    
    if not contact.get('ip_address'):
        print(f"No IP address available for {contact['full_name']}.")
        return
    
    # Verify file exists
    file_path = Path(file_path)
    if not file_path.exists():
        print(f"File {file_path} does not exist.")
        return
    
    # Get file info
    file_name = file_path.name
    file_size = file_path.stat().st_size
    
    # Connect to contact and request transfer
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.settimeout(30)
        
        print(f"Attempting to connect to {contact['ip_address']}:{PORT}...")
        try:
            client.connect((contact['ip_address'], PORT))
            print("Connection established.")
        except socket.timeout:
            print("Connection timed out. Possible issues:")
            print("- Contact is offline")
            print("- Firewall blocking port", PORT)
            print("- Network connectivity issues")
            client.close()
            return
        except ConnectionRefusedError:
            print("Connection refused. Is the contact running SecureDrop?")
            client.close()
            return
        
        # Send transfer request
        request = {
            'type': 'file_transfer_request',
            'from_email': current_user['email'],
            'file_name': file_name,
            'file_size': file_size,
            'sequence_num': SEQUENCE_NUM
        }
        client.send(json.dumps(request).encode())
        
        # Get response
        response_data = client.recv(BUFFER_SIZE)
        if not response_data:
            print("No response from contact.")
            client.close()
            return
            
        response = json.loads(response_data.decode())
        if response.get('type') != 'file_transfer_response' or not response.get('accepted', False):
            print(f"Contact declined the file transfer.")
            client.close()
            return
        
        print("Contact has accepted the transfer request. Starting file transfer...")
        
        # Increment sequence number
        SEQUENCE_NUM += 1
        
        # Send file in chunks with encryption
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            bytes_sent = 0
            chunk_size = 4096  # 4KB chunks
            
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Encrypt the chunk
                encrypted_chunk = encrypt_message(chunk.hex(), contact['public_key'])
                client.send(encrypted_chunk.encode())
                
                # Update hash and progress
                file_hash.update(chunk)
                bytes_sent += len(chunk)
                
                # Print progress
                percent = (bytes_sent / file_size) * 100
                print(f"Progress: {percent:.1f}%", end='\r')
            
            # Send hash verification
            final_message = {
                'type': 'file_transfer_complete',
                'file_hash': file_hash.hexdigest(),
                'sequence_num': SEQUENCE_NUM
            }
            client.send(json.dumps(final_message).encode())
        
        print("\nFile has been successfully transferred.")
        client.close()
        
    except Exception as e:
        print(f"Error during file transfer: {e}")
        if 'client' in locals():
            client.close()

def handle_file_transfer_request(client_socket, contacts_file):
    """Handle incoming file transfer requests"""
    global current_user, SEQUENCE_NUM
    
    try:
        data = client_socket.recv(BUFFER_SIZE)
        request = json.loads(data.decode())
        
        if request.get('type') != 'file_transfer_request':
            return
            
        # Verify sequence number is greater than last seen
        if request.get('sequence_num', 0) <= SEQUENCE_NUM:
            response = {
                'type': 'file_transfer_response',
                'accepted': False,
                'reason': 'Invalid sequence number (possible replay attack)'
            }
            client_socket.send(json.dumps(response).encode())
            return
        
        SEQUENCE_NUM = request['sequence_num']
        
        # Show transfer request to user
        print(f"\nContact '{request['from_email']}' is sending a file.")
        print(f"File: {request['file_name']} ({request['file_size']} bytes)")
        choice = input("Accept (y/n)? ").strip().lower()
        
        if choice != 'y':
            response = {
                'type': 'file_transfer_response',
                'accepted': False
            }
            client_socket.send(json.dumps(response).encode())
            return
        
        # Create directory for received files if it doesn't exist
        if not Path(FILE_TRANSFER_DIR).exists():
            Path(FILE_TRANSFER_DIR).mkdir()
            
        file_path = Path(FILE_TRANSFER_DIR) / request['file_name']
        
        response = {
            'type': 'file_transfer_response',
            'accepted': True
        }
        client_socket.send(json.dumps(response).encode())
        
        # Receive file
        file_hash = hashlib.sha256()
        bytes_received = 0
        file_size = request['file_size']
        
        with open(file_path, 'wb') as f:
            while bytes_received < file_size:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                    
                try:
                    # Try to parse as JSON (might be the final hash message)
                    final_message = json.loads(data.decode())
                    if final_message.get('type') == 'file_transfer_complete':
                        # Verify file hash
                        if final_message.get('file_hash') == file_hash.hexdigest():
                            print("\nFile transfer complete. Hash verified.")
                        else:
                            print("\nFile transfer complete but hash verification failed!")
                        break
                    continue
                except json.JSONDecodeError:
                    pass
                
                # Decrypt the chunk
                try:
                    decrypted_data = decrypt_message(data.decode(), current_user['private_key'])
                    chunk = bytes.fromhex(decrypted_data)
                except Exception as e:
                    print(f"Error decrypting chunk: {e}")
                    continue
                
                f.write(chunk)
                file_hash.update(chunk)
                bytes_received += len(chunk)
                
                # Print progress
                percent = (bytes_received / file_size) * 100
                print(f"Progress: {percent:.1f}%", end='\r')
        
    except Exception as e:
        print(f"Error handling file transfer: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    users_file = Path('users.json')
    contacts_file = Path('contacts.json')
    users = []
    
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
            elif command == 'verify':
                force_mutual_check(contacts_file)
            elif command == 'help':
                print_help()
            elif command.startswith('send'):
                parts = command.split()
                if len(parts) != 3:
                    print("Usage: send <email> <file_path>")
                else:
                    _, email, file_path = parts
                    send_file(email, file_path)
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for a list of commands.")
    except KeyboardInterrupt:
        running = False
        print("\nExiting SecureDrop. Goodbye!")
        sys.exit(0)