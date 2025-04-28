# SecureDrop Project

## Overview
SecureDrop is a secure peer-to-peer file transfer application that enables users to safely share files over a local network with verified contacts.

## Contributors and authors:
- Ayoub Darkaoui (Ayoub_Darkaoui@student.uml.edu)
- Arthea Valderrama (Arthea_Valderrama@student.uml.edu) 
- McKenna Blake (McKenna_Blake@student.uml.edu)

## Milestones

### Milestone 1: User Registration
Arthea Valderrama

- Secure user account creation
- Password requirements enforcement
- RSA key pair generation
- Secure storage of user credentials

### Milestone 2: User Login
Arthea Valderrama

- Secure authentication system
- Password validation
- Session management
- Protection against unauthorized access

### Milestone 3: Adding Contacts
Arthea Valderrama

- Contact management system
- Contact information storage
- Secure contact verification process

### Milestone 4: Listing Contacts
Ayoub Darkaoui

Implementation of contact listing functionality including:
- Real-time contact status display
- Network discovery mechanism
- Mutual connection verification
- Network presence detection
- File transfer availability checking

Features:
- Display all contacts with their:
  - Name
  - Email
  - Online/Offline status
  - Mutual verification status
- Show contacts available for file transfer
- Automatic status updates
- Secure verification process

### Milestone 5: Secure File Transfer
McKenna Blake

- End-to-end encryption. Confidentiality: AES symmetric encryption in CFB mode
- File integrity verification. SHA-256 hash function
- Progress tracking
- Transfer authorization
- Secure key exchange
- Replay Attack Mitigation: sequence numbers with random seed

Features:
- Secure transfer of files between users. Guarantees files are identical
- Ensure the file exists. Ensure the recipient is mutual, online, and has a valid IP
- Allow recipient to deny file transfer
- Transfer large files in chunks, and detect if connection drops or if file is corrupted
- Ensure file is saved to recipient before success
- Timeout detection

## Technical Requirements
- Python 3.6+
- Network connectivity
- Required libraries:
  - cryptography
  - socket
  - json

## Usage
1. Start the application:
```bash
python3 secure_drop.py
```

2. Available commands:
```
add    -> Add a new contact
list   -> List all contacts and statuses
send   -> Transfer file to contact
help   -> Show commands
exit   -> Exit SecureDrop
```

## Security Features
- RSA encryption for key exchange
- AES encryption for file transfer
- SHA-512 password hashing
- Mutual contact verification
- Secure network communication