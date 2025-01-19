import os
from tkinter import *
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64


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
    root.geometry("700x750")  # Increased window size for better fitting
    root.configure(bg="#faf3dd")  # Pastel background color

    # Generate keys section
    def generate_keys_gui():
        private_key, public_key = generate_keys()
        priv_key_entry.delete('1.0', END)
        pub_key_entry.delete('1.0', END)
        priv_key_entry.insert(END, private_key.decode())
        pub_key_entry.insert(END, public_key.decode())

    Label(root, text="PGP Algorithm Implementation", font=('Helvetica', 18), bg="#faf3dd", fg="#374785").pack(pady=15)

    # Public Key
    Label(root, text="Public Key:", bg="#faf3dd", font=('Helvetica', 12)).pack(anchor=W, padx=20)
    pub_key_entry = Text(root, height=6, width=80, bg="#e1e8f0", wrap=WORD)
    pub_key_entry.pack(pady=5, padx=20)

    # Private Key
    Label(root, text="Private Key:", bg="#faf3dd", font=('Helvetica', 12)).pack(anchor=W, padx=20)
    priv_key_entry = Text(root, height=6, width=80, bg="#e1e8f0", wrap=WORD)
    priv_key_entry.pack(pady=5, padx=20)

    # Generate Key Button
    Button(root, text="Generate Keys", command=generate_keys_gui, bg="#92b4ec", fg="black", font=('Helvetica', 12)).pack(pady=10)

    # Message Entry
    Label(root, text="Message:", bg="#faf3dd", font=('Helvetica', 12)).pack(anchor=W, padx=20)
    message_entry = Text(root, height=6, width=80, bg="#e1e8f0", wrap=WORD)
    message_entry.pack(pady=5, padx=20)

    # Output Entry
    Label(root, text="Encrypted/Decrypted Message:", bg="#faf3dd", font=('Helvetica', 12)).pack(anchor=W, padx=20)
    output_entry = Text(root, height=6, width=80, bg="#e1e8f0", wrap=WORD)
    output_entry.pack(pady=5, padx=20)

    # Button Frames for alignment
    button_frame1 = Frame(root, bg="#faf3dd")
    button_frame1.pack(pady=10)

    button_frame2 = Frame(root, bg="#faf3dd")
    button_frame2.pack(pady=10)

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

    # Encrypt/Decrypt Buttons in one line
    Button(button_frame1, text="Encrypt", command=encrypt_gui, bg="#ffb6b9", fg="black", font=('Helvetica', 12)).pack(side=LEFT, padx=10)
    Button(button_frame1, text="Decrypt", command=decrypt_gui, bg="#ffb6b9", fg="black", font=('Helvetica', 12)).pack(side=LEFT, padx=10)

    # Sign/Verify Buttons in another line
    Button(button_frame2, text="Sign Message", command=sign_gui, bg="#ffcbf2", fg="black", font=('Helvetica', 12)).pack(side=LEFT, padx=10)
    Button(button_frame2, text="Verify Signature", command=verify_gui, bg="#ffcbf2", fg="black", font=('Helvetica', 12)).pack(side=LEFT, padx=10)

    root.mainloop()


# Run the GUI
if __name__ == "__main__":
    create_gui()
