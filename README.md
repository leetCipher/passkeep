# Passkeep password manager

Passkeep is a proof-of-concept password manager that is good for personal use.

## Installation

You will need to first install the required modules in the requirements.txt file:

```bash
pip3 install -r requirements.txt
chmod +x passkeep.py
./passkeep.py
```

## Screenshots
### Displaying records
![Alt text](/screenshots/display-records.png?raw=true)
### Adding records
![Alt text](/screenshots/add-records.png?raw=true)
### Editing records
![Alt text](/screenshots/edit-records.png?raw=true)
### Deleting records
![Alt text](/screenshots/delete-records.png?raw=true)
### Updating decryption key
![Alt text](/screenshots/update-decryption-key.png?raw=true)

## Security
Passkeep uses AES-CBC modes of operation to encrypt all the credentials in the "passwords.db" file and uses SHA-256 hash function to hash and validate the key that is used for both encryption and decryption.

## Features
* Add, Edit, Delete credentials
* Change the encryption/decryption key
* Passwords generation
* Backup database/credentials
* Erase database/credentials

## Bugs
I tested the application several times to make sure it's bug free (that doesn't mean it is), so in case of any bugs (insecure cryptographic implementations/weaknesses only), please, report the issue.