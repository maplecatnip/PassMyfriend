from cryptography.fernet import Fernet
import sqlite3
import getpass  # For hiding the input of passwords
import secrets
import string


db_path = "/path/to/your/database_directory"


# Key management
def generate_key(password):
    # Use the password to generate a key
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted_key = fernet.encrypt(password.encode())
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    with open("key.key", "wb") as encrypted_key_file:
        encrypted_key_file.write(encrypted_key)
    return key

def load_key(password):
    # Decrypt and load the key
    with open("secret.key", "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)
    with open("key.key", "rb") as encrypted_key_file:
        encrypted_key = encrypted_key_file.read()
    decrypted_password = fernet.decrypt(encrypted_key).decode()
    if password == decrypted_password:
        return key
    else:
        return None

# Encryption & Decryption
def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message)
    return decrypted_message.decode()



def create_db():
    print(f"Connecting to database at: {db_path}")
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    connection.commit()
    connection.close()


# User Interface and Functionality
def menu():
    print("\nPassword Manager")
    print("1. Add a new password")
    print("2. Retrieve a password")
    print("3. Update a password")
    print("4. Delete a password")
    print("5. Quit")
    choice = input("Enter your choice: ")
    return choice


# Generate_password Function
def generate_password(length=20):
    if length < 4:
        raise ValueError("Password length must be at least 4 characters")

    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in string.punctuation for c in password)):
            break

    return password


def add_password(key):
    website = input("Website: ")
    username = input("Username: ")

    # Offer choice between entering a password manually or generating one
    choice = input("Would you like to (1) enter a password manually or (2) generate a secure password? Enter 1 or 2: ")
    if choice == '1':
        password = getpass.getpass("Enter your password: ")
    elif choice == '2':
        password = generate_password(20)
        print(f"Generated password: {password}")
    else:
        print("Invalid choice. Defaulting to manual password entry.")
        password = getpass.getpass("Enter your password: ")

    encrypted_password = encrypt_message(password, key)


    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute('''
        INSERT INTO accounts (website, username, password)
        VALUES (?, ?, ?)
    ''', (website, username, encrypted_password))

    connection.commit()
    connection.close()
    print("Password added successfully.")


def get_password(key):
    website = input("Website: ")
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    # Ensure the query parameter is passed as a tuple
    cursor.execute('SELECT username, password FROM accounts WHERE website = ?', (website,))
    account_info = cursor.fetchone()
    connection.close()

    if account_info:
        username, encrypted_password = account_info
        password = decrypt_message(encrypted_password, key)
        print(f"Website: {website}\nUsername: {username}, Password: {password}")
    else:
        # This will now correctly print if an account for the website is not found
        print(f"Account for {website} not found.")


def update_password(key):
    website = input("Website: ")

    # Offer choice between entering a new password manually or generating one
    choice = input(
        "Would you like to (1) enter a new password manually or (2) generate a secure password? Enter 1 or 2: ")
    if choice == '1':
        new_password = getpass.getpass("New Password: ")
    elif choice == '2':
        new_password = generate_password(20)
        print(f"Generated password: {new_password}")
    else:
        print("Invalid choice. Defaulting to manual password entry.")
        new_password = getpass.getpass("New Password: ")

    encrypted_password = encrypt_message(new_password, key)

    # Use the absolute path for the database
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute('''
        UPDATE accounts
        SET password = ?
        WHERE website = ?
    ''', (encrypted_password, website))

    connection.commit()

    if cursor.rowcount == 0:
        print("Account not found.")
    else:
        print("Password updated successfully.")

    connection.close()

def delete_password():
    website = input("Website to delete: ")
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute('DELETE FROM accounts WHERE website = ?', (website,))
    connection.commit()
    connection.close()
    if cursor.rowcount == 0:
        print("Account not found.")
    else:
        print("Account deleted successfully.")

def main():
    # Initialization or login to get the encryption key
    try:
        password = input("Enter your master password: ")  # Or use getpass.getpass() for hidden input
        key = load_key(password)
        if key is None:
            print("Incorrect master password. Exiting...")
            return
    except FileNotFoundError:
        print("No encryption key found, generating a new one...")
        password = input("Set a new master password: ")  # Or use getpass.getpass() for hidden input
        key = generate_key(password)  # Adjust generate_key to return the key directly

    while True:
        print("\nPassword Manager")
        print("1. Add a new password")
        print("2. Retrieve a password")
        print("3. Update a password")
        print("4. Delete a password")
        print("5. Quit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            add_password(key)  # Pass 'key' to the function
        elif choice == '2':
            get_password(key)  # Pass 'key' to the function
        elif choice == '3':
            # Assuming there's an update_password function
            update_password(key)  # Pass 'key' to the function
        elif choice == '4':
            # Assuming there's a delete_password function
            delete_password()  # Pass 'key' to the function, if it needs it
        elif choice == '5':
            print("Exiting password manager.")
            break
        else:
            print("Invalid action. Please choose between 1-5.")

if __name__ == "__main__":
    create_db()  # Ensure the database and the 'accounts' table exists
    main()
