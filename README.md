# Simple Encrypted Messaging Tool (AES-256)

## Overview
Simple Python-based messaging tool for secure communications. It leverages military-grade AES-256-GCM encryption. Please note, this tool is provided mainly for demonstration and testing purposes; you should not rely on it if you don't fully understand the code.

<br>


![gui](https://github.com/user-attachments/assets/de845922-6912-4837-9c5d-c8168fde3377)



## Usage
The application has four main tabs:
1. **Recipients** - Manage your encryption partners
2. **Encrypt Message** - Create messages to send
3. **Decrypt Message** - Decrypt messages you receive
4. **Configuration** - Settings
 
### Adding a New Recipient
1. Click the **Recipients** tab
2. Click **"Add New Recipient"**
3. Enter the recipient's name (avoid special characters)
4. Either:
   - Click **"Generate Key"** to create a new AES-256 key
   - Paste an existing Base64-encoded key shared by your contact

### Key Sharing (Critical Security Step)
You must share encryption keys securely with your contacts through a separate, secure channel such as:
- In-person exchange
- Secure file sharing service
- Encrypted email
- Signal/WhatsApp/Telegram

**Never share keys through:**
- Regular email
- SMS/text messages
- Social media

### Encrypting Messages
1. Go to the **Encrypt Message** tab
2. Select your recipient from the dropdown menu
3. Click **"Load Key"** - the status should show green checkmark
4. Type your message in the text area
5. Click **"Encrypt Message"**
6. Click **"Copy to Clipboard"**
7. Send the encrypted message through any communication channel

### Decrypting Messages
1. Go to the **Decrypt Message** tab
2. Select the sender from the dropdown (must match who sent the message)
3. Click **"Load Key"**
4. Paste the encrypted message in the input area
5. Click **"Decrypt Message"**
6. Read the decrypted message in the output area

### Troubleshooting
**"Invalid key format" error:**
- Ensure the key is exactly 32 bytes when Base64 decoded
- Check for extra spaces or characters in the key
- Regenerate the key if corrupted

**"Failed to decrypt" error:**
- Verify you're using the correct recipient/sender pairing
- Ensure the encrypted message wasn't modified during transmission
- Check that you're using the same key that was used for encryption


## What This Tool Protects Against
✅ Message interception during transmission  
✅ Unauthorized access to message content  
✅ Message tampering/modification  
✅ Passive surveillance of communications

## What This Tool Does NOT Protect Against
❌ Keyloggers on compromised computers  
❌ Screen recording malware  
❌ Physical access to unlocked devices  
❌ Social engineering attacks  
❌ Metadata analysis (who/when you're messaging)

### Message Format
```
nonce (12 bytes) + ciphertext (variable) + authentication_tag (16 bytes)
```
Encoded in Base64 with header markers for easy identification.

## Legal and Compliance
Strong encryption may be subject to export control regulations in some countries.

Remember that the security of your communications depends not just on tools, but on your overall security practices and OPSEC.
