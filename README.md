# PassMyfriend
To store, retrieve, update, and delete passwords using encryption for enhanced security.
PassMyfriend is a simple yet secure and user-friendly way to manage your passwords locally for people who barely know coding and cybersecurity. Utilizing strong encryption, it ensures that your passwords are stored securely and are accessible only through a master password you set. It's simply adaptable across various platforms.

# Features
Secure Password Storage: Encrypts passwords before saving them to the database.
Password Retrieval: Decrypts and displays passwords stored in the database.
Password Management: Allows adding new passwords, updating existing ones, and deleting passwords.
Password Generation: Generates password that meets password polices (lowercase letter, uppercase letter, digit, and special character)
Master Password: Secures access to the password manager with a master password.


# Requirements
Python 3.x
cryptography Python package

# Setup
Install Python 3.x: Ensure Python 3.x is installed on your system.

pip install cryptography

Clone or Download the Script: Obtain the script files and place them in a directory of your choice.

# Before use: 
1. Specify database path: db_path = "/absolute/path/to/your/database.db"

2. For Command prompt: cd /absolute/path/to/your/database.db



# First Use
On the first launch, you'll be prompted to set a master password. This password encrypts your key and secures access to the password manager.
It uses symmetric encryption (Fernet) for securing passwords. It's crucial to remember the master password, as it's required to access the stored passwords. Loss of the master password or the key file (secret.key) will result in the inability to decrypt your passwords.

# Contributing
Contributions are welcome. Please open an issue to discuss your ideas or submit a pull request.

# License
This project is open-source and available under the MIT License. See the LICENSE file for more details.
