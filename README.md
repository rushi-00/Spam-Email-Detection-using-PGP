# SPAM EMAIL DETECTION USING PGP
 
<h4>Project Overview : </h4><br>
Pretty Good Privacy (PGP) is a powerful and widely-used encryption method that combines symmetric and public-key cryptography to ensure secure communication. 
By encrypting data with a symmetric session key and protecting that key using the recipient’s public key, PGP guarantees confidentiality. 
Its digital signature feature also provides message integrity and authentication, ensuring that data remains untampered and the sender’s identity is verified. 


<h4>Result<h4> : 

![image](https://github.com/user-attachments/assets/c9f14fd3-2f48-4e60-80fa-c2fbd693076b)


 1. *Key Generation:*
   - Click on the "Generate Keys" button. This will generate a pair of private and public keys, which will automatically appear in the corresponding text fields.

 2. *Message to Encrypt:*
   - *Public Key*: The public key generated from the "Generate Keys" step will be used for encryption.
   - *Message*: Enter a message in the "Message" text box. Example: 
     
     This is a secret message.
     

 3. *Encrypt the Message:*
   - Click the "Encrypt" button, and the encrypted version of the message will appear in the "Encrypted/Decrypted Message" field.

 4. *Message to Decrypt:*
   - *Private Key*: The private key generated from the "Generate Keys" step will be used for decryption.
   - Copy the encrypted message from the "Encrypted/Decrypted Message" field and paste it into the "Message" text box.
   - Click the "Decrypt" button, and the original message will appear in the "Encrypted/Decrypted Message" field.

 5. *Sign the Message:*
   - *Private Key*: Use the private key generated earlier.
   - *Message*: Use any message you'd like to sign. Example:
     
     Important document for signature verification.
     
   - Click "Sign Message" to generate a signature in the "Encrypted/Decrypted Message" field.

 6. *Verify the Signature:*
   - *Public Key*: Use the public key generated earlier.
   - *Message*: Use the same message that was signed.
   - *Signature*: Paste the signature from the "Encrypted/Decrypted Message" field into the "Encrypted/Decrypted Message" box.
   - Click "Verify Signature" to verify the validity of the signature.

This is how you can test the full flow of your PGP GUI system.
