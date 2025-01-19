import os
from tkinter import *
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
import base64
import os

# Generate a pair of keys (Private and Public)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Serialize private key
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key, pem_public_key

# Encrypt message with Public Key
def encrypt_message(public_key, message):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_message)

# Decrypt message with Private Key
def decrypt_message(private_key, encrypted_message):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# Sign a message with Private Key
def sign_message(private_key, message):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature)

# Verify signature with Public Key
def verify_signature(public_key, message, signature):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    signature = base64.b64decode(signature)
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Create GUI
def create_gui():
    root = Tk()
    root.title("PGP Cryptography")
    root.geometry("500x600")
    
    # Generate keys section
    def generate_keys_gui():
        private_key, public_key = generate_keys()
        priv_key_entry.insert(END, private_key.decode())
        pub_key_entry.insert(END, public_key.decode())

    Label(root, text="PGP Algorithm Implementation", font=('Helvetica', 16)).pack(pady=20)

    # Public Key
    Label(root, text="Public Key:").pack()
    pub_key_entry = Text(root, height=5, width=60)
    pub_key_entry.pack(pady=5)

    # Private Key
    Label(root, text="Private Key:").pack()
    priv_key_entry = Text(root, height=5, width=60)
    priv_key_entry.pack(pady=5)

    # Generate Key Button
    Button(root, text="Generate Keys", command=generate_keys_gui).pack(pady=10)

    # Encrypt/Decrypt Message
    Label(root, text="Message:").pack()
    message_entry = Text(root, height=5, width=60)
    message_entry.pack(pady=5)

    Label(root, text="Encrypted/Decrypted Message:").pack()
    output_entry = Text(root, height=5, width=60)
    output_entry.pack(pady=5)

    def encrypt_gui():
        pub_key = pub_key_entry.get("1.0", END).strip().encode()
        message = message_entry.get("1.0", END).strip()
        encrypted = encrypt_message(pub_key, message)
        output_entry.delete('1.0', END)
        output_entry.insert(END, encrypted.decode())

    def decrypt_gui():
        priv_key = priv_key_entry.get("1.0", END).strip().encode()
        encrypted_message = message_entry.get("1.0", END).strip()
        decrypted = decrypt_message(priv_key, encrypted_message)
        output_entry.delete('1.0', END)
        output_entry.insert(END, decrypted)

    def sign_gui():
        priv_key = priv_key_entry.get("1.0", END).strip().encode()
        message = message_entry.get("1.0", END).strip()
        signature = sign_message(priv_key, message)
        output_entry.delete('1.0', END)
        output_entry.insert(END, signature.decode())

    def verify_gui():
        pub_key = pub_key_entry.get("1.0", END).strip().encode()
        message = message_entry.get("1.0", END).strip()
        signature = output_entry.get("1.0", END).strip()
        is_valid = verify_signature(pub_key, message, signature)
        if is_valid:
            messagebox.showinfo("Signature Verification", "Signature is valid!")
        else:
            messagebox.showerror("Signature Verification", "Signature is invalid!")

    Button(root, text="Encrypt", command=encrypt_gui).pack(pady=5)
    Button(root, text="Decrypt", command=decrypt_gui).pack(pady=5)
    Button(root, text="Sign Message", command=sign_gui).pack(pady=5)
    Button(root, text="Verify Signature", command=verify_gui).pack(pady=5)

    root.mainloop()

# Run the GUI
if _name_ == "_main_":
    create_gui()