# SecureDrop Project

## Overview
SecureDrop is a secure peer-to-peer file transfer application that enables users to safely share files over a local network with verified contacts.

## Contributors and authors:
- Ayoub Darkaoui (Ayoub_Darkaoui@student.uml.edu)
- Arthea Valderrama (Arthea_Valderrama@student.uml.edu) 
- McKenna Blake (McKenna_Blake@student.uml.edu)

## Milestones

### Milestone 1: User Registration
**Assigned to: *
- Secure user account creation
- Password requirements enforcement
- RSA key pair generation
- Secure storage of user credentials

### Milestone 2: User Login
- Secure authentication system
- Password validation
- Session management
- Protection against unauthorized access

### Milestone 3: Adding Contacts
- Contact management system
- Contact information storage
- Secure contact verification process

### Milestone 4: Listing Contacts

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
- End-to-end encryption
- File integrity verification
- Progress tracking
- Transfer authorization
- Secure key exchange

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