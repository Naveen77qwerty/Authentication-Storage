import bcrypt # Used for hashing and salting passwords for security
import json  # To store the DATA
import shlex # To input data
import random # To generate random characters 
import string # used to alphabetical generate charaactors
from cryptography.fernet import Fernet  # Encrypting and Decrypting passwords

# Functions for password management
def storage_data(acc, name, encrypted_pass, hash_pass):#storage of data
    return {
        "Account": acc,
        "Username": name,
        "password": encrypted_pass,
        "hashedpassword": hash_pass.decode()
    }

def password_strength():
    while True:
        user_password = input("Enter a password: ")
        
        # List to track issues
        issues = []
        
        # Check password length
        if not (5 <= len(user_password) <= 12):
            issues.append("\n"+"\t"*5+"Password should be 5-12 characters long.")
        
        # Check for lowercase letters
        if not any(c.islower() for c in user_password):
            issues.append("\n"+"\t"*5+"Password needs at least one lowercase letter.")
        
        # Check for uppercase letters
        if not any(c.isupper() for c in user_password):
            issues.append("\n"+"\t"*5+"Password needs at least one uppercase letter.")
        
        # Check for digits
        if not any(c.isdigit() for c in user_password):
            issues.append("\n"+"\t"*5+"Password needs at least one number.")
        
        # Check for special characters
        if not any(c in "`~_-?:;,><.!@[]#$%^&()*" for c in user_password):
            issues.append("\n"+"\t"*5+"Password needs at least one special character.")
        
        # If there are issues, print them and ask again
        if issues:
            print("Your password did not meet the following requirements:")
            for issue in issues:
                print(f"- {issue}")
        else:
            # Password meets all conditions, return it
            print("Password is Strong!")
            return user_password

def add_to_json(data, filename="data.json"):
# Adding data to the json file    
    try:
        with open(filename, 'r', encoding="utf-8") as file:
            existing_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    existing_data.append(data)
    with open(filename, 'w', encoding="utf-8") as file:
        json.dump(existing_data, file, indent=4)

def read_from_json(filename="data.json"):
#Obtaining passwords from json file
    try:
        with open(filename, 'r', encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_json(data, filename="data.json"):
#Updating passwords to the json file
    with open(filename, 'w', encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def password_generator(key):
#Generating random password
    non_alphanumeric = "`~_-?:;,><.!@[]#$%^&()*"
    return key[:4] + str(random.randint(0, 9)) + \
           random.choice(string.ascii_uppercase) + \
           random.choice(string.ascii_lowercase) + \
           random.choice(non_alphanumeric)

def encrypt_password(password, cipher):
#Password encryption and decoding the password to save it in json file
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, cipher):
#Password decryption 
    return cipher.decrypt(encrypted_password.encode()).decode()

def hash_password(password):
#Hashing password and generating salt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(hashed_password, provided_password):
#Checks the given and hashed password.
    return bcrypt.checkpw(provided_password.encode(), hashed_password)

def generate_key():
#Generates a new Fernet key and writes it to 'secret.key'.
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
#Loads the Fernet key from 'secret.key'. Generates a new one if invalid or missing.
    try:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
            if len(key) != 44:  # Fernet key must be 44 characters (32 bytes)
                raise ValueError("The key in secret.key is invalid.")
            return key
    except (FileNotFoundError, ValueError):
        print("Invalid or missing Fernet key! Generating a new one...")
        return generate_key()

# Load or regenerate the key
key = load_key()
cipher = Fernet(key)

# Main Password Setup and Login
def setup_main_password():
    main_password = input("\n"+"\t"*5+"Set your main password: ")
    hashed_main_password = hash_password(main_password)
    with open("main_password.json", "w") as file:
        json.dump({"main_password": hashed_main_password.decode()}, file)
    print("\n"+"\t"*5+"Main password set successfully.")

def login_main_password():
    try:
        with open("main_password.json", "r") as file:
            stored_password = json.load(file)["main_password"].encode()
    except (FileNotFoundError, json.JSONDecodeError):
        print("\n"+"\t"*5+"Main password not set. Setting up now.")
        setup_main_password()
        return True

    for _ in range(3):
        print("*"*180)
        password = input("\n"+"\t"*5+"Enter main password: ")
        if check_password(stored_password, password):
            print("\n"+"\t"*5+"Main password correct.")
            print("*"*180)
            return True
        print("\n"+"\t"*5+"Incorrect password.")
        u=input("\n"+"\t"*5+"Forgot password? Type * to reset all data\n"+"\t"*5+"Or try again? Type anything else:")
    
        if u == "*":
            reset_all_data()
            main_loop()
        if u!="*":
            main_loop()  
    return False
    
def reset_all_data():
    # Clear out existing data files
    open("data.json", "w").close()
    open("main_password.json", "w").close()

    # Generate a new Fernet key and write it to secret.key
    new_key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(new_key)
    
    print("\n"+"\t"*5+"All data reset. Set up a new main password.")
    setup_main_password()  # Ensure the main password is set immediately after reset
    main_loop()
    
# Main features
def update_password(account, username, old_password, new_password):
#Updating Password
    print("*"*180)    
    data = read_from_json()
    for entry in data:
        if entry["Account"] == account and entry["Username"] == username:
            if check_password(entry["hashedpassword"].encode(), old_password):
                encrypted_pass = encrypt_password(new_password, cipher)
                hashed_pass = hash_password(new_password).decode()
                entry["password"] = encrypted_pass
                entry["hashedpassword"] = hashed_pass
                save_json(data)
                print("\n"+"\t"*5+"Password updated successfully.")
                return
            else:
                print("\n"+"\t"*5+"Old password incorrect.")
                return
    print("\n"+"\t"*5+"Account not found.")

def show_password(account, username):
#Displaying the password
    print("*"*180)
    data = read_from_json()
    for entry in data:
        if entry["Account"] == account and entry["Username"] == username:
            decrypted_password = decrypt_password(entry["password"], cipher)
            print("\n"+"\t"*5+"Password for:",decrypted_password)
            return
    print("\n"+"\t"*5+"Account not found.")

def delete_account(account, username):
#Deleting the Password
    print("*"*180)
    data = read_from_json()
    new_data = [entry for entry in data if not (entry["Account"] == account and entry["Username"] == username)]
    if len(new_data) < len(data):
        save_json(new_data)
        print("\n"+"\t"*5+"Account deleted successfully.")
    else:
        print("\n"+"\t"*5+"Account not found.")

# Main Program Flow
def main_loop():
    if login_main_password() :
        while True:
            print("\n"+"\t"*5+"Options:\n"+"\t"*5+"1. Add Account\n"+"\t"*5+"2. Update Password\n"+"\t"*5+"3. Show Password\n"+"\t"*5+"4. Delete Account\n"+"\t"*5+"5. Exit")
            choice = input("\n"+"\t"*5+"Enter choice (1-5): ")
            print("*"*180)
            if choice == "1":    
                while True:
                    
                    user_input1 = shlex.split(input("\n"+"\t"*5+"Enter Account, Username: "))
                    ch=input("\n"+"\t"*5+"1.User password or 2.Generate password: ")
                    
                    if ch == '1' and user_input1[0]!='' and user_input1[1]!='' and len(user_input1)==2:
                        user_password=password_strength()
                        encrypted_pass = encrypt_password(user_password, cipher)
                        hashed_pass = hash_password(user_password)
                        
                        add_to_json(storage_data(user_input1[0], user_input1[1], encrypted_pass, hashed_pass))
                        print("\n"+"\t"*5+"A new set of Account, Username and Password has been succesfully added")
                        break
                    
                    elif ch == '2'and user_input1[0]!='' and user_input1[1]!='' and len(user_input1)==2:
                        user_name=input("\n"+"\t"*5+"Enter a key word: ")
                        generated_pass = password_generator(user_name)
                        
                        print("\n"+"\t"*5+"The generated password is:",generated_pass)
                        
                        encrypted_pass = encrypt_password(generated_pass, cipher)
                        hashed_pass = hash_password(generated_pass)
                        
                        add_to_json(storage_data(user_input1[0], user_input1[1], encrypted_pass, hashed_pass))
                        print("\n"+"\t"*5+"A new set of Account, Username and Generated Password has been succesfully added")
                        
                        break
                    else:
                        print("\n"+"\t"*5+"Invalid input format\nTry again")
                        continue
                        
                    
            elif choice == "2":
                print("\n"+"\t"*5+"UPDATING ACCOUNT")
                user_input2 = shlex.split(input("\n"+"\t"*5+"Enter Account and Username to Update Password: "))
                
                ch=int(input("\n"+"\t"*5+"1.User password or 2.Generate password(The generated password will shown and saved automatically): "))
                if ch == 1 and user_input2[0]!='' and user_input2[1]!=''and len(user_input2)==2:
                    user_input4 = shlex.split(input("\n"+"\t"*5+"Enter old password and new password: "))
                    generated_pass = password_generator(user_input2[1])
                    
                    print("\n"+"\t"*5+"The generated password is:",generated_pass)
                    update_password(user_input2[0], user_input2[1], user_input4[0], generated_pass)
                    
                elif ch == 2 and user_input2[0]!='' and user_input2[1]!=''and len(user_input2)==2:
                    user_input6 = shlex.split(input("\n"+"\t"*5+"Enter old password: "))
                    generated_pas=password_strength()
                    
                    update_password(user_input2[0], user_input2[1], user_input6[0], generated_pas)
                    print("\n"+"\t"*5+"The Account has been Updated!!")
                    
                else:
                    print("\n"+"\t"*5+"Give input in proper format")    
                        
            elif choice == "3":
                print("\n"+"\t"*5+"DISPLAYING ACCOUNT")
                
                user_input3 = shlex.split(input("\n"+"\t"*5+"Enter Account and Username to View Password: "))
                
                if user_input3[0]!='' and user_input3[1]!=''and len(user_input3)==2:
                    show_password(user_input3[0], user_input3[1])
                else:
                    print("\n"+"\t"*5+"Give input in proper format")
                    
            elif choice == "4":
                print("\n"+"\t"*5+"DELETING ACCOUNT")
                
                user_input5 = shlex.split(input("\n"+"\t"*5+"Enter Account and Username to delete: "))
                
                print("\n"+"\t"*5+"Account Successfully deleted!!")
                delete_account(user_input5[0], user_input5[1])
                
            elif choice == "5":
                break
            
            else:
                print("\n"+"\t"*5+"Invalid choice. Please try again.")

main_loop()


