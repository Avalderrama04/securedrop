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

def login(users_file):
    while True: 
        email = input("Enter Email Address: ").strip()
        password = getpass.getpass("Enter Password: ") 
        if len(password) == 0:
            print("empty password")
            password = getpass.getpass("Enter Password: ") 
                    

        with open(users_file, 'r') as f:
            users = json.load(f)
        email_sucess = None
        for user in users:
            if user['email'] == email:
                email_sucess = user
                break
        if not email_sucess:
            print("Email not found, try again")
            continue
        if authenticate(password, email_sucess['password']):
            print("Welcome to SecureDrop.")
            return email_sucess
        elif not authenticate(password, email_sucess['password']): 
            print("Email and Password Combination Invalid. ") #test if email is not in json? 
            email = input("Enter Email Address: ").strip()
            password = getpass.getpass("Enter Password: ") 
        
                    
                            
def make_contact(contacts_file):
    full_name = input("Enter Full Name: ").strip()
    email = input("Enter Email Address: ").strip()
    contacts = []
    contacts_data = {
        'full_name': full_name,
        'email': email,
        
        #'public_key': public_key,
        #'private_key': private_key  #encrypt private key in future milestones? 
    }
    
    contacts.append(contacts_data)
    with open(contacts_file, 'w') as f:
        json.dump(contacts, f, indent=4)
    print(f"Contact {full_name} added successfully.")

    print("Contact Added. ")
if __name__ == "__main__":
    users_file = Path('users.json')
    contacts_file = Path('contacts.json')
    users = []
    
    if users_file.exists(): 
        with open(users_file, 'r') as f:
            users = json.load(f)
    else:
        print("No users are registered with this client.")#delete users.json for demo
        choice = input("Do you want to register a new user (y/n)? ").strip().lower()
        if choice == 'y':
            make_user(choice)
            print("Exiting SecureDrop.")
            sys.exit(0)

        if choice == 'n':
            print("Exiting SecureDrop.")
            sys.exit(0)
        
    
    sucessful_login = login(users_file)
    print("Type \"help\" For Commands.")
    while True:
        command = input().strip()
        if command == 'exit':
            sys.exit(0)
            break
        elif command == 'add':
            make_contact(contacts_file)
        elif command == 'help':
            print(" \"add\" -> Add a new contact \n \"list\" -> List all online contacts \n \"send\" -> Transfer file to contact \n \"exit\" -> Exit SecureDrop")
                
            
    