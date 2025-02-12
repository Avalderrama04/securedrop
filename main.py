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
    hash = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    return hash 

def authenticate(password,hash):
    
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
        'private_key': private_key  #encrypt private key in future milestones? 
    }
    
    users.append(user_data)
    with open(users_file, 'w') as f:
        json.dump(users, f, indent=4)
    
    print("User Registered.")
    print("Exiting SecureDrop.")

def login(users_file):
    password_sucess = 0
    email_sucess = 0
    email = input("Enter Email Address: ").strip()
    password = getpass.getpass("Enter Password: ") 

    with open(users_file, 'r') as f:
        users = json.load(f)
    
    for user in users:
            while True:   
                if user['email'] != email:
                    if not authenticate(password, user['password']) or password.len == 0:
                        print("Email and Password Combination Invalid. ") #test if email is not in json? 

                        email = input("Enter Email Address: ").strip()
                        password = getpass.getpass("Enter Password: ") 
                else:
                    print("Welcome to SecureDrop.")
                    break
                    return True
                    
                            

if __name__ == "__main__":
    users_file = Path('users.json')
    users = []
    
    if users_file.exists(): 
        with open(users_file, 'r') as f:
            users = json.load(f)
    else:
        print("No users are registered with this client.")#delete users.json for demo
        choice = input("Do you want to register a new user (y/n)? ").strip().lower()
        if choice == 'n':
            print("Exiting SecureDrop.")
            sys.exit(0)
        elif choice == 'y':
            make_user(choice)
            print("Exiting SecureDrop.")
            sys.exit(0)

    
    sucessful_login = login(users_file)
    print("Type \"help\" For Commands.")
    help = input().strip()
    if help == 'help':
          print(" \"add\" -> Add a new contact \n \"list\" -> List all online contacts \n \"send\" -> Transfer file to contact \n \"exit\" -> Exit SecureDrop")
    
    command = input().strip()