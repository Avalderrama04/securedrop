import json
import sys
import getpass
from pathlib import Path
import crypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#generate and store mutual authentication for future milestones, dont need this implemented just yet
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes( #find a way to encript this too, if we can
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_pem, public_pem

"""
crypt.METHOD_SHA512 A Modular Crypt Format method with 16 character salt and 86 character hash. 
Strongest method but we can consider others 
"""
def secure_password(password):
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512)) 

if __name__ == "__main__":
    users_file = Path('users.json')
    users = []
    
    if users_file.exists(): 
        with open(users_file, 'r') as f:
            users = json.load(f)
    
    if not users:
        print("No users are registered with this client.")#delete users.json for demo
    
    choice = input("Do you want to register a new user (y/n)? ").strip().lower()
    if choice != 'y':
        print("Exiting SecureDrop.")
        sys.exit(0)
    
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
        'private_key': private_key  #encrypt private key in future milestones? 
    }
    
    users.append(user_data)
    with open(users_file, 'w') as f:
        json.dump(users, f, indent=4)
    
    print("User Registered.")
    print("Exiting SecureDrop.")