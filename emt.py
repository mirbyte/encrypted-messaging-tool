import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
from tkinter.simpledialog import Dialog, askstring
import ctypes
import secrets
import re
import html
import hashlib
from configparser import ConfigParser

# --- DPI Awareness ---
try:
    ctypes.windll.shcore.SetProcessDpiAwarenessContext(-2)
except (AttributeError, OSError):
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            # Fallback: no DPI awareness
            pass

# Constants
AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
PBKDF2_ITERATIONS = 100000
SALT_SIZE = 32
MAX_RECIPIENT_NAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 1000000

class SecureMemory:
    """Utility class for secure memory operations"""
    @staticmethod
    def secure_clear(data):
        """Securely clear sensitive data from memory"""
        if isinstance(data, bytearray):
            # Clear bytearray in place
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, str):
            # For strings, we can't directly clear them as they're immutable
            # But we can try to overwrite using ctypes (with caveats)
            try:
                import ctypes
                # This is a best-effort approach and has limitations
                str_address = id(data)
                str_length = len(data.encode('utf-8'))
                ctypes.memset(str_address, 0, str_length)
            except:
                pass  # Fallback: rely on Python's garbage collection
        # For other types, rely on Python's garbage collection
        
    @staticmethod
    def create_secure_bytes(size):
        """Create a secure bytearray for sensitive data"""
        return bytearray(size)


class InputSanitizer:
    """Utility class for input sanitization"""
    @staticmethod
    def sanitize_recipient_name(name):
        """Sanitize recipient name input"""
        if not name:
            return ""
        
        # Remove HTML tags and escape special characters
        name = html.escape(name.strip())
        
        # Remove potentially dangerous characters
        dangerous_chars = r'[<>:"/\\|?*\x00-\x1f]'
        name = re.sub(dangerous_chars, '', name)
        
        # Limit length
        if len(name) > MAX_RECIPIENT_NAME_LENGTH:
            name = name[:MAX_RECIPIENT_NAME_LENGTH]
        
        # Remove leading/trailing whitespace and normalize
        name = ' '.join(name.split())
        
        return name
    
    @staticmethod
    def validate_recipient_name(name):
        sanitized = InputSanitizer.sanitize_recipient_name(name)
        
        if not sanitized:
            return False, "Recipient name cannot be empty"
        
        if len(sanitized) < 1:
            return False, "Recipient name is too short"
        
        if sanitized != name:
            return False, "Recipient name contains invalid characters"
        
        return True, sanitized
    
    @staticmethod
    def sanitize_message(message):
        if not message:
            return ""
        
        # Limit message length
        if len(message) > MAX_MESSAGE_LENGTH:
            message = message[:MAX_MESSAGE_LENGTH]
        
        return message

class CryptoValidator:
    """Utility class for cryptographic validation"""
    @staticmethod
    def validate_key_entropy(key_bytes):
        """Check if key has sufficient entropy"""
        if len(key_bytes) != AES_KEY_SIZE:
            return False, "Invalid key length"
        
        # Check for obvious patterns
        if len(set(key_bytes)) < 16:  # Should have diverse byte values
            return False, "Key appears to have low entropy"
        
        # Check for common weak patterns
        if key_bytes == b'\x00' * AES_KEY_SIZE:
            return False, "Key is all zeros"
        
        if key_bytes == b'\xff' * AES_KEY_SIZE:
            return False, "Key is all ones"
        
        # Check for sequential patterns
        is_sequential = all(key_bytes[i] == (key_bytes[0] + i) % 256 for i in range(len(key_bytes)))
        if is_sequential:
            return False, "Key appears to be sequential"
        
        return True, "Key entropy is acceptable"
    
    @staticmethod
    def generate_key_fingerprint(key_bytes):
        """Generate a fingerprint for key identification"""
        hasher = hashlib.sha256()
        hasher.update(key_bytes)
        fingerprint = hasher.digest()[:8]  # First 8 bytes
        return base64.b64encode(fingerprint).decode('utf-8')
    
    @staticmethod
    def validate_base64_key(key_str):
        """Validate and analyze a base64 encoded key"""
        try:
            key_bytes = base64.b64decode(key_str)
            
            # Check length
            if len(key_bytes) != AES_KEY_SIZE:
                return False, f"Key must be {AES_KEY_SIZE} bytes, got {len(key_bytes)}", None, None
            
            # Check entropy
            entropy_valid, entropy_msg = CryptoValidator.validate_key_entropy(key_bytes)
            if not entropy_valid:
                return False, entropy_msg, None, None
            
            # Generate fingerprint
            fingerprint = CryptoValidator.generate_key_fingerprint(key_bytes)
            
            return True, "Key is cryptographically valid", key_bytes, fingerprint
            
        except Exception as e:
            return False, f"Invalid Base64 format: {str(e)}", None, None

class UIConfig:
    def __init__(self, config_file="ui_config.ini"):
        self.config_file = config_file
        self.parser = ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Load UI configuration from file"""
        # Default values
        defaults = {
            'colors': {
                'dark_bg': '#3C3C3C',
                'light_fg': '#EAEAEA',
                'entry_bg': '#3C3C3C',
                'button_bg': '#4A4A4A',
                'button_fg': '#FFFFFF',
                'accent_color': '#000000',
                'success_color': '#77DD77',
                'error_color': '#FF6B6B'
            },
            'geometry': {
                'window_width': '865',
                'window_height': '900',
                'text_height': '8',
                'entry_width': '30',
                'button_padding': '5'
            },
            'fonts': {
                'main_font': 'Segoe UI',
                'main_size': '10',
                'button_size': '10',
                'tab_size': '11',
                'signature_size': '7'
            }
        }
        
        if os.path.exists(self.config_file):
            self.parser.read(self.config_file)
        
        # Ensure all sections and defaults exist
        for section, options in defaults.items():
            if not self.parser.has_section(section):
                self.parser.add_section(section)
            for key, value in options.items():
                if not self.parser.has_option(section, key):
                    self.parser.set(section, key, value)
        
        self.save_config()
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            self.parser.write(f)
    
    def get(self, section, key):
        """Get configuration value"""
        return self.parser.get(section, key)
    
    def getint(self, section, key):
        """Get integer configuration value"""
        return self.parser.getint(section, key)
    
    def set(self, section, key, value):
        """Set configuration value"""
        self.parser.set(section, key, str(value))
        self.save_config()


class MasterPasswordDialog(Dialog):
    def __init__(self, parent, title, is_first_time=False, ui_config=None):
        self.is_first_time = is_first_time
        self.password = None
        self.reset_requested = False
        self.parent = parent
        self.ui_config = ui_config or UIConfig()
        self.style = ttk.Style(parent)
        super().__init__(parent, title)

    def body(self, master):
        dark_bg = self.ui_config.get('colors', 'dark_bg')
        light_fg = self.ui_config.get('colors', 'light_fg')
        entry_width = self.ui_config.getint('geometry', 'entry_width')
        
        master.configure(bg=dark_bg)
        
        if self.is_first_time:
            ttk.Label(master, text="Create Master Password:", 
                     background=dark_bg, foreground=light_fg).grid(row=0, column=0, padx=5, pady=5, sticky='w')
            self.password_entry = ttk.Entry(master, width=entry_width, show='*')
            self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
            
            ttk.Label(master, text="Confirm Password:", 
                     background=dark_bg, foreground=light_fg).grid(row=1, column=0, padx=5, pady=5, sticky='w')
            self.confirm_entry = ttk.Entry(master, width=entry_width, show='*')
            self.confirm_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        else:
            ttk.Label(master, text="Enter Master Password:", 
                     background=dark_bg, foreground=light_fg).grid(row=0, column=0, padx=5, pady=5, sticky='w')
            self.password_entry = ttk.Entry(master, width=entry_width, show='*')
            self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
            
            reset_btn = ttk.Button(master, text="Reset App", command=self.reset_app)
            reset_btn.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

        master.columnconfigure(1, weight=1)
        return self.password_entry


    def reset_app(self):
        if messagebox.askyesno("Reset Application", 
                              "This will delete ALL data including recipients and reset the app to default state.\n\nAre you sure?", 
                              parent=self.parent):
            self.reset_requested = True
            self.destroy()


    def validate(self):
        if self.is_first_time:
            password = self.password_entry.get()
            confirm = self.confirm_entry.get()
            
            if not password:
                messagebox.showwarning("Validation", "Password is required", parent=self.parent)
                return False
            
            if len(password) < 4:
                messagebox.showwarning("Validation", "Password must be at least 4 characters long", parent=self.parent)
                return False
                
            if password != confirm:
                messagebox.showwarning("Validation", "Passwords do not match", parent=self.parent)
                return False
                
            self.password = password
        else:
            self.password = self.password_entry.get()
            if not self.password:
                messagebox.showwarning("Validation", "Password is required", parent=self.parent)
                return False
                
        return True


    def apply(self):
        pass

class RecipientDialog(Dialog):
    def __init__(self, parent, title, recipient=None, ui_config=None):
        self.recipient = recipient or {"name": "", "key": ""}
        self.parent = parent
        self.ui_config = ui_config or UIConfig()
        self.style = ttk.Style(parent)
        super().__init__(parent, title)

    def body(self, master):
        dark_bg = self.ui_config.get('colors', 'dark_bg')
        light_fg = self.ui_config.get('colors', 'light_fg')
        entry_bg = self.ui_config.get('colors', 'entry_bg')
        entry_width = self.ui_config.getint('geometry', 'entry_width')
        text_height = self.ui_config.getint('geometry', 'text_height')
        
        master.configure(bg=dark_bg)
        
        ttk.Label(master, text="Recipient Name:", 
                 background=dark_bg, foreground=light_fg).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.name_entry = ttk.Entry(master, width=entry_width)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.name_entry.insert(0, self.recipient["name"])
        
        ttk.Label(master, text="Shared Secret Key (Base64):", 
                 background=dark_bg, foreground=light_fg).grid(row=1, column=0, padx=5, pady=5, sticky='nw')
        self.key_text = scrolledtext.ScrolledText(master, width=40, height=text_height//2, 
                                                 bg=entry_bg, fg=light_fg, insertbackground=light_fg)
        self.key_text.grid(row=1, column=1, padx=5, pady=5, sticky='nsew')
        self.key_text.insert('1.0', self.recipient["key"])

        ttk.Button(master, text="Generate Key", command=self.generate_key).grid(row=1, column=2, padx=5, pady=5)
        
        # Key validation info
        self.validation_label = ttk.Label(master, text="", background=dark_bg, foreground=light_fg)
        self.validation_label.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky='ew')
        
        # Real-time validation
        self.key_text.bind('<KeyRelease>', self.validate_key_realtime)
        self.name_entry.bind('<KeyRelease>', self.validate_name_realtime)

        master.columnconfigure(1, weight=1)
        master.rowconfigure(1, weight=1)
        return self.name_entry


    def validate_name_realtime(self, event=None):
        name = self.name_entry.get()
        valid, msg = InputSanitizer.validate_recipient_name(name)
        
        if not name:
            self.validation_label.config(text="")
        elif valid:
            self.validation_label.config(text="✓ Name is valid", 
                                       foreground=self.ui_config.get('colors', 'success_color'))
        else:
            self.validation_label.config(text=f"⚠ {msg}", 
                                       foreground=self.ui_config.get('colors', 'error_color'))

    def validate_key_realtime(self, event=None):
        key = self.key_text.get('1.0', 'end-1c').strip()
        
        if not key:
            self.validation_label.config(text="")
            return
        
        valid, msg, key_bytes, fingerprint = CryptoValidator.validate_base64_key(key)
        
        if valid:
            self.validation_label.config(text=f"✓ Key valid - Fingerprint: {fingerprint}", 
                                       foreground=self.ui_config.get('colors', 'success_color'))
        else:
            self.validation_label.config(text=f"⚠ {msg}", 
                                       foreground=self.ui_config.get('colors', 'error_color'))

    def generate_key(self):
        """Generate a new random AES-256 key and display it"""
        key_bytes = SecureMemory.create_secure_bytes(AES_KEY_SIZE)
        try:
            # Generate cryptographically secure random bytes
            random_bytes = secrets.token_bytes(AES_KEY_SIZE)
            key_bytes[:] = random_bytes
            
            b64_key = base64.b64encode(key_bytes).decode('utf-8')
            self.key_text.delete('1.0', tk.END)
            self.key_text.insert('1.0', b64_key)
            
            # Validate the generated key
            self.validate_key_realtime()
            
        finally:
            # Securely clear the key from memory
            SecureMemory.secure_clear(key_bytes)

    def validate(self):
        name = self.name_entry.get().strip()
        key = self.key_text.get('1.0', 'end-1c').strip()

        # Validate name
        valid_name, name_msg = InputSanitizer.validate_recipient_name(name)
        if not valid_name:
            messagebox.showwarning("Validation", name_msg, parent=self.parent)
            return False

        # Validate key
        valid_key, key_msg, key_bytes, fingerprint = CryptoValidator.validate_base64_key(key)
        if not valid_key:
            messagebox.showwarning("Validation", key_msg, parent=self.parent)
            return False

        return True

    def apply(self):
        name = InputSanitizer.sanitize_recipient_name(self.name_entry.get().strip())
        key = self.key_text.get('1.0', 'end-1c').strip()
        
        self.result = {
            "name": name,
            "key": key
        }

class E2EMessagingTool:
    def __init__(self, root):
        self.root = root
        self.ui_config = UIConfig()
        
        # Initialize secure variables
        self.master_key = SecureMemory.create_secure_bytes(AES_KEY_SIZE)
        self.salt = None
        self.current_encryption_key = None
        self.current_decryption_key = None
        
        # Configure window
        width = self.ui_config.getint('geometry', 'window_width')
        height = self.ui_config.getint('geometry', 'window_height')
        self.root.title("Encrypted Messaging Tool (AES-GCM) v0.3")
        self.root.geometry(f"{width}x{height}")
        self.root.resizable(True, True)
        
        # Bind cleanup to window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.config_file = "config.json"
        self.apply_dark_theme()
        
        # Initialize master key for recipients encryption
        if not self.initialize_master_key():
            root.destroy()
            return

        self.recipients = []
        self.load_recipients()

        self.setup_ui()

        # Signature
        signature_font = (self.ui_config.get('fonts', 'main_font'), 
                         self.ui_config.getint('fonts', 'signature_size'), 'italic')
        signature_label = ttk.Label(self.root, text="github/mirbyte",
                                   font=signature_font, anchor='e')
        signature_label.pack(side='bottom', fill='x', padx=55, pady=0)

    def on_closing(self):
        self.secure_cleanup()
        self.root.destroy()

    def secure_cleanup(self):
        if hasattr(self, 'master_key') and self.master_key:
            SecureMemory.secure_clear(self.master_key)
        
        if hasattr(self, 'current_encryption_key') and self.current_encryption_key:
            SecureMemory.secure_clear(self.current_encryption_key)
        
        if hasattr(self, 'current_decryption_key') and self.current_decryption_key:
            SecureMemory.secure_clear(self.current_decryption_key)

    def setup_ui(self):
        padding = self.ui_config.getint('geometry', 'button_padding')
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=padding*2, pady=padding*2)

        self.recipient_tab = ttk.Frame(self.notebook)
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.encrypt_tab, text="Encrypt Message")
        self.notebook.add(self.decrypt_tab, text="Decrypt Message")
        self.notebook.add(self.recipient_tab, text="Recipients")
        self.notebook.add(self.config_tab, text="Configuration")

        self.setup_recipient_tab()
        self.setup_encryption_tab()
        self.setup_decryption_tab()
        self.setup_config_tab()
        self.populate_recipient_list()

    def setup_config_tab(self):
        padding = self.ui_config.getint('geometry', 'button_padding')
        
        config_frame = ttk.LabelFrame(self.config_tab, text="Security Settings")
        config_frame.pack(fill='x', padx=padding*2, pady=padding)
        
        ttk.Button(config_frame, text="Change Master Password",
                   command=self.change_master_password).pack(side='left', padx=padding)
        
        ttk.Button(config_frame, text="Reset Application",
                   command=self.reset_application_data).pack(side='left', padx=padding)
        
        # Memory cleanup
        memory_frame = ttk.LabelFrame(self.config_tab, text="Memory Management")
        memory_frame.pack(fill='x', padx=padding*2, pady=padding)
        
        ttk.Button(memory_frame, text="Clear Sensitive Memory",
                   command=self.manual_memory_cleanup).pack(side='left', padx=padding)
        
        # UI settings
        ui_frame = ttk.LabelFrame(self.config_tab, text="UI Configuration")
        ui_frame.pack(fill='both', expand=True, padx=padding*2, pady=padding)
        
        ttk.Label(ui_frame, text="UI settings are stored in ui_config.ini").pack(padx=padding, pady=padding)
        ttk.Button(ui_frame, text="Reset UI to Defaults",
                   command=self.reset_ui_config).pack(padx=padding, pady=padding)

    def manual_memory_cleanup(self):
        self.secure_cleanup()
        messagebox.showinfo("Memory Cleanup", "Sensitive memory has been cleared")

    def reset_ui_config(self):
        """Reset UI configuration to defaults"""
        if os.path.exists(self.ui_config.config_file):
            os.remove(self.ui_config.config_file)
        messagebox.showinfo("UI Reset", "UI configuration reset. Please restart the application.")

    def reset_application_data(self):
        """Reset application to default state by removing all data files"""
        if messagebox.askyesno("Reset Application", 
                              "This will delete ALL data including recipients and reset the app to default state.\n\nAre you sure?"):
            self.secure_cleanup()
            
            # Remove config files
            for file in [self.config_file, "recipients.json", "ui_config.ini"]:
                if os.path.exists(file):
                    os.remove(file)
            
            messagebox.showinfo("Reset Complete", "Application has been reset to default state.\nPlease restart the application.")
            self.root.destroy()

    def initialize_master_key(self):
        """Initialize or verify master password for encrypting recipients data"""
        config = self.load_config()
        
        if 'salt' not in config:
            # First time setup
            dialog = MasterPasswordDialog(self.root, "Setup Master Password", 
                                        is_first_time=True, ui_config=self.ui_config)
            
            if dialog.reset_requested:
                self.reset_application_data()
                return False
                
            if not dialog.password:
                messagebox.showerror("Required", "Master password is required to use this application")
                return False
                
            # Generate new salt and derive key
            self.salt = secrets.token_bytes(SALT_SIZE)
            config['salt'] = base64.b64encode(self.salt).decode('utf-8')
            self.save_config(config)
            self.derive_key_from_password(dialog.password)
            
            # Secure cleanup of password
            SecureMemory.secure_clear(dialog.password)
            return True
        else:
            # Existing setup
            self.salt = base64.b64decode(config['salt'])
            dialog = MasterPasswordDialog(self.root, "Enter Master Password", 
                                        is_first_time=False, ui_config=self.ui_config)
            
            if dialog.reset_requested:
                self.reset_application_data()
                return False
                
            if not dialog.password:
                return False
                
            self.derive_key_from_password(dialog.password)
            
            # Secure cleanup of password
            SecureMemory.secure_clear(dialog.password)
            
            # Verify password by trying to decrypt recipients file
            try:
                self.load_recipients()
                return True
            except Exception:
                messagebox.showerror("Invalid Password", "Incorrect master password")
                SecureMemory.secure_clear(self.master_key)
                return False

    def derive_key_from_password(self, password):
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=self.salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        password_bytes = password.encode('utf-8')
        derived_key = kdf.derive(password_bytes)
        
        # Copy to secure master key
        self.master_key[:] = derived_key
        
        # Secure cleanup
        SecureMemory.secure_clear(password_bytes)
        SecureMemory.secure_clear(derived_key)

    def encrypt_recipients_data(self, data):
        """Encrypt recipients data using master key"""
        if not self.master_key or all(b == 0 for b in self.master_key):
            raise ValueError("Master key not initialized")
            
        # Convert to JSON string
        json_string = json.dumps(data, indent=2)
        plaintext = json_string.encode('utf-8')
        
        # Generate random nonce
        nonce = secrets.token_bytes(GCM_NONCE_SIZE)
        
        try:
            # Create cipher and encrypt
            cipher = Cipher(
                algorithms.AES(bytes(self.master_key)),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Combine nonce + ciphertext + tag
            encrypted_data = nonce + ciphertext + encryptor.tag
            return base64.b64encode(encrypted_data).decode('utf-8')
        finally:
            # Secure cleanup
            SecureMemory.secure_clear(plaintext)

    def decrypt_recipients_data(self, encrypted_data):
        """Decrypt recipients data using master key"""
        if not self.master_key or all(b == 0 for b in self.master_key):
            raise ValueError("Master key not initialized")
            
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extract components
            nonce = encrypted_bytes[:GCM_NONCE_SIZE]
            tag = encrypted_bytes[-GCM_TAG_SIZE:]
            ciphertext = encrypted_bytes[GCM_NONCE_SIZE:-GCM_TAG_SIZE]
            
            # Create cipher and decrypt
            cipher = Cipher(
                algorithms.AES(bytes(self.master_key)),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Parse JSON
            json_string = plaintext.decode('utf-8')
            result = json.loads(json_string)
            
            # Secure cleanup
            SecureMemory.secure_clear(plaintext)
            
            return result
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt recipients data: {str(e)}")

    def change_master_password(self):
        current_password = askstring("Current Password", 
                                   "Enter current master password:", 
                                   show='*', parent=self.root)
        if not current_password:
            return
            
        # Verify current password
        test_key = SecureMemory.create_secure_bytes(AES_KEY_SIZE)
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=self.salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            derived_key = kdf.derive(current_password.encode('utf-8'))
            test_key[:] = derived_key
            
            if bytes(test_key) != bytes(self.master_key):
                messagebox.showerror("Invalid", "Current password is incorrect")
                return
                
        finally:
            SecureMemory.secure_clear(test_key)
            SecureMemory.secure_clear(current_password)
            
        new_password = askstring("New Password", 
                               "Enter new master password (min 8 chars):", 
                               show='*', parent=self.root)
        if not new_password or len(new_password) < 8:
            messagebox.showerror("Invalid", "New password must be at least 8 characters")
            return
            
        confirm_password = askstring("Confirm New Password", 
                                   "Confirm new master password:", 
                                   show='*', parent=self.root)
        if new_password != confirm_password:
            messagebox.showerror("Mismatch", "New passwords do not match")
            SecureMemory.secure_clear(new_password)
            SecureMemory.secure_clear(confirm_password)
            return
            
        try:
            # Generate new salt and key
            self.salt = secrets.token_bytes(SALT_SIZE)
            self.derive_key_from_password(new_password)
            
            # Update config and re-encrypt recipients
            config = self.load_config()
            config['salt'] = base64.b64encode(self.salt).decode('utf-8')
            self.save_config(config)
            self.save_recipients()
            
            messagebox.showinfo("Success", "Master password changed successfully")
        finally:
            SecureMemory.secure_clear(new_password)
            SecureMemory.secure_clear(confirm_password)

    def apply_dark_theme(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')

        dark_bg = self.ui_config.get('colors', 'dark_bg')
        light_fg = self.ui_config.get('colors', 'light_fg')
        entry_bg = self.ui_config.get('colors', 'entry_bg')
        button_bg = self.ui_config.get('colors', 'button_bg')
        button_fg = self.ui_config.get('colors', 'button_fg')
        accent_color = self.ui_config.get('colors', 'accent_color')
        main_font = self.ui_config.get('fonts', 'main_font')
        main_size = self.ui_config.getint('fonts', 'main_size')
        button_size = self.ui_config.getint('fonts', 'button_size')
        tab_size = self.ui_config.getint('fonts', 'tab_size')

        self.root.configure(bg=dark_bg)
        style.configure(".", background=dark_bg, foreground=light_fg, font=(main_font, main_size))
        style.configure("TFrame", background=dark_bg)
        style.configure("TLabel", background=dark_bg, foreground=light_fg)
        style.configure("TLabelframe", background=dark_bg, foreground=light_fg)
        style.configure("TLabelframe.Label", background=dark_bg, foreground=light_fg)
        style.configure("TButton", background=button_bg, foreground=button_fg, font=(main_font, button_size, 'bold'))
        style.map("TButton",
                  background=[('active', accent_color)],
                  foreground=[('active', light_fg)])

        style.configure("TEntry", fieldbackground=entry_bg, foreground=light_fg, insertcolor=light_fg)
        style.configure("TCombobox", fieldbackground=entry_bg, foreground=light_fg, 
                       selectbackground=entry_bg, selectforeground=light_fg)
        style.map("TCombobox",
                  fieldbackground=[('readonly', entry_bg)],
                  selectbackground=[('readonly', entry_bg)],
                  selectforeground=[('readonly', light_fg)],
                  foreground=[('readonly', light_fg)])

        style.configure("TNotebook", background=dark_bg, tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background=button_bg, foreground=light_fg, 
                       padding=[10, 5], font=(main_font, tab_size, 'bold'))
        style.map("TNotebook.Tab",
                  background=[("selected", accent_color), ('active', dark_bg)],
                  foreground=[("selected", light_fg), ('active', light_fg)])

        style.configure("Treeview",
                        background=entry_bg,
                        foreground=light_fg,
                        fieldbackground=entry_bg,
                        rowheight=25)
        style.map("Treeview",
                  background=[('selected', accent_color)],
                  foreground=[('selected', light_fg)])

        style.configure("Treeview.Heading",
                        background=button_bg,
                        foreground=light_fg,
                        font=(main_font, main_size, 'bold'))
        style.map("Treeview.Heading",
                  background=[('active', accent_color)])

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as f:
                return json.load(f)
        return {}

    def save_config(self, data):
        with open(self.config_file, "w") as f:
            json.dump(data, f, indent=2)

    def setup_recipient_tab(self):
        """Setup recipient management tab"""
        padding = self.ui_config.getint('geometry', 'button_padding')
        
        button_frame = ttk.Frame(self.recipient_tab)
        button_frame.pack(fill='x', padx=padding*2, pady=padding*2)

        ttk.Button(button_frame, text="Add New Recipient",
                   command=self.add_recipient).pack(side='left', padx=padding)

        self.edit_btn = ttk.Button(button_frame, text="Edit Selected",
                                   command=self.edit_recipient, state='disabled')
        self.edit_btn.pack(side='left', padx=padding)

        self.remove_btn = ttk.Button(button_frame, text="Remove Selected",
                                     command=self.remove_recipient, state='disabled')
        self.remove_btn.pack(side='left', padx=padding)

        list_frame = ttk.LabelFrame(self.recipient_tab, text="Saved Recipients")
        list_frame.pack(fill='both', expand=True, padx=padding*2, pady=padding)

        columns = ("name", "fingerprint")
        self.recipient_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", selectmode="browse"
        )

        self.recipient_tree.heading("name", text="Recipient Name")
        self.recipient_tree.heading("fingerprint", text="Key Fingerprint")
        self.recipient_tree.column("name", width=300, anchor='w')
        self.recipient_tree.column("fingerprint", width=200, anchor='w')

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.recipient_tree.yview)
        self.recipient_tree.configure(yscrollcommand=scrollbar.set)

        self.recipient_tree.pack(side='left', fill='both', expand=True, padx=padding, pady=padding)
        scrollbar.pack(side='right', fill='y', padx=(0, padding), pady=padding)

        self.recipient_tree.bind("<<TreeviewSelect>>", self.on_recipient_select)

    def on_recipient_select(self, event):
        selected = self.recipient_tree.selection()
        if selected:
            self.edit_btn.config(state='normal')
            self.remove_btn.config(state='normal')
        else:
            self.edit_btn.config(state='disabled')
            self.remove_btn.config(state='disabled')

    def populate_recipient_list(self):
        self.recipient_tree.delete(*self.recipient_tree.get_children())
        
        for recipient in self.recipients:
            # Generate fingerprint for display
            try:
                valid, msg, key_bytes, fingerprint = CryptoValidator.validate_base64_key(recipient["key"])
                if valid:
                    display_fingerprint = fingerprint
                else:
                    display_fingerprint = "Invalid Key"
            except:
                display_fingerprint = "Error"
            
            self.recipient_tree.insert("", "end", values=(recipient["name"], display_fingerprint))
        
        self.update_recipient_dropdowns()

    def add_recipient(self):
        dialog = RecipientDialog(self.root, "Add Recipient", ui_config=self.ui_config)
        if dialog.result:
            # Check for duplicate names
            existing_names = [r["name"].lower() for r in self.recipients]
            if dialog.result["name"].lower() in existing_names:
                messagebox.showerror("Duplicate", "A recipient with this name already exists")
                return
            
            self.recipients.append(dialog.result)
            self.save_recipients()
            self.populate_recipient_list()

    def edit_recipient(self):
        selected = self.recipient_tree.selection()
        if not selected: 
            return

        item = self.recipient_tree.item(selected[0])
        name = item["values"][0]
        recipient_data = next((r for r in self.recipients if r["name"] == name), None)
        if not recipient_data: 
            return

        dialog = RecipientDialog(self.root, "Edit Recipient", recipient_data, ui_config=self.ui_config)
        if dialog.result:
            # Check for duplicate names (excluding current)
            existing_names = [r["name"].lower() for r in self.recipients if r["name"] != recipient_data["name"]]
            if dialog.result["name"].lower() in existing_names:
                messagebox.showerror("Duplicate", "A recipient with this name already exists")
                return
                
            recipient_data["name"] = dialog.result["name"]
            recipient_data["key"] = dialog.result["key"]
            self.save_recipients()
            self.populate_recipient_list()

    def remove_recipient(self):
        selected = self.recipient_tree.selection()
        if not selected: 
            return

        item = self.recipient_tree.item(selected[0])
        name = item["values"][0]

        if not messagebox.askyesno("Confirm", f"Remove recipient '{name}'?", parent=self.root): 
            return

        self.recipients = [r for r in self.recipients if r["name"] != name]
        self.save_recipients()
        self.populate_recipient_list()
        self.recipient_tree.selection_remove(selected)

    def load_recipients(self):
        if os.path.exists("recipients.json"):
            with open("recipients.json", "r") as f:
                file_content = f.read().strip()
                
            if file_content:
                # Always expect encrypted format
                self.recipients = self.decrypt_recipients_data(file_content)
            else:
                self.recipients = []
        else:
            self.recipients = []

    def save_recipients(self):
        encrypted_data = self.encrypt_recipients_data(self.recipients)
        with open("recipients.json", "w") as f:
            f.write(encrypted_data)

    def setup_encryption_tab(self):
        """Setup message encryption tab"""
        padding = self.ui_config.getint('geometry', 'button_padding')
        text_height = self.ui_config.getint('geometry', 'text_height')
        entry_width = self.ui_config.getint('geometry', 'entry_width')
        
        recipient_frame = ttk.Frame(self.encrypt_tab)
        recipient_frame.pack(fill='x', padx=padding*2, pady=(padding*2, padding))

        ttk.Label(recipient_frame, text="Recipient:").pack(side='left', padx=(0, padding))

        self.recipient_var = tk.StringVar()
        self.recipient_dropdown = ttk.Combobox(
            recipient_frame,
            textvariable=self.recipient_var,
            state="readonly",
            width=entry_width
        )
        self.recipient_dropdown.pack(side='left', fill='x', expand=True, padx=padding)

        ttk.Button(recipient_frame, text="Load Key",
                   command=self.load_selected_recipient).pack(side='left', padx=padding)

        status_frame = ttk.Frame(self.encrypt_tab)
        status_frame.pack(fill='x', padx=padding*2, pady=(0, padding))

        ttk.Label(status_frame, text="Key Status:").pack(side='left', padx=(0, padding))

        self.loaded_recipient_var = tk.StringVar(value="None")
        self.status_indicator = ttk.Label(
            status_frame,
            textvariable=self.loaded_recipient_var,
            foreground=self.ui_config.get('colors', 'error_color')
        )
        self.status_indicator.pack(side='left', padx=padding)

        input_frame = ttk.LabelFrame(self.encrypt_tab, text="Message to Encrypt")
        input_frame.pack(fill='x', padx=padding*2, pady=padding)

        self.message_input = scrolledtext.ScrolledText(input_frame, height=text_height,
                                                      bg=self.ui_config.get('colors', 'entry_bg'),
                                                      fg=self.ui_config.get('colors', 'light_fg'),
                                                      insertbackground=self.ui_config.get('colors', 'light_fg'))
        self.message_input.pack(fill='both', expand=True, padx=padding*2, pady=padding*2)
        self.message_input.bind('<KeyRelease>', self.toggle_encrypt_button)

        output_frame = ttk.LabelFrame(self.encrypt_tab, text="Encrypted Message")
        output_frame.pack(fill='both', expand=True, padx=padding*2, pady=padding)

        self.encrypted_output = scrolledtext.ScrolledText(output_frame, height=text_height,
                                                         bg=self.ui_config.get('colors', 'entry_bg'),
                                                         fg=self.ui_config.get('colors', 'light_fg'),
                                                         insertbackground=self.ui_config.get('colors', 'light_fg'))
        self.encrypted_output.pack(fill='both', expand=True, padx=padding*2, pady=padding*2)
        self.encrypted_output.config(state='disabled')

        button_frame_encrypt = ttk.Frame(self.encrypt_tab)
        button_frame_encrypt.pack(fill='x', padx=padding*2, pady=padding)

        self.encrypt_button = ttk.Button(button_frame_encrypt, text="Encrypt Message", command=self.encrypt_message)
        self.encrypt_button.pack(side='left', padx=padding)

        ttk.Button(button_frame_encrypt, text="Copy to Clipboard", command=self.copy_encrypted).pack(side='left', padx=padding)
        ttk.Button(button_frame_encrypt, text="Clear", command=self.clear_encrypt).pack(side='right', padx=padding)

        self.toggle_encrypt_button()

    def toggle_encrypt_button(self, event=None):
        """Toggle encrypt button state"""
        message = self.message_input.get("1.0", "end-1c")
        sanitized = InputSanitizer.sanitize_message(message)
        
        if not sanitized or not self.current_encryption_key:
            self.encrypt_button.config(state='disabled')
        else:
            self.encrypt_button.config(state='normal')

    def update_recipient_dropdowns(self):
        """Update recipient dropdown lists"""
        names = [r["name"] for r in self.recipients]
        self.recipient_dropdown["values"] = names
        
        if hasattr(self, 'decrypt_recipient_dropdown'):
            self.decrypt_recipient_dropdown["values"] = names
        
        if names:
            self.recipient_dropdown.config(state="readonly")
            if hasattr(self, 'decrypt_recipient_dropdown'):
                self.decrypt_recipient_dropdown.config(state="readonly")
        else:
            self.recipient_dropdown.config(state="disabled")
            if hasattr(self, 'decrypt_recipient_dropdown'):
                self.decrypt_recipient_dropdown.config(state="disabled")

        # Reset selections
        self.recipient_var.set("")
        if hasattr(self, 'decrypt_recipient_var'):
            self.decrypt_recipient_var.set("")
        
        self.loaded_recipient_var.set("None")
        self.status_indicator.config(foreground=self.ui_config.get('colors', 'error_color'))
        
        # Clear current keys
        if self.current_encryption_key:
            SecureMemory.secure_clear(self.current_encryption_key)
            self.current_encryption_key = None
        
        if hasattr(self, 'current_decryption_key') and self.current_decryption_key:
            SecureMemory.secure_clear(self.current_decryption_key)
            self.current_decryption_key = None
        
        self.toggle_encrypt_button()

    def load_selected_recipient(self):
        """Load selected recipient's key for encryption"""
        name = self.recipient_var.get()
        if not name:
            messagebox.showwarning("No Recipient", "Select a recipient first.", parent=self.root)
            return

        recipient = next((r for r in self.recipients if r["name"] == name), None)
        if not recipient:
            messagebox.showwarning("Not Found", f"No recipient named '{name}'.", parent=self.root)
            return

        try:
            valid, msg, key_bytes, fingerprint = CryptoValidator.validate_base64_key(recipient["key"])
            
            if not valid:
                raise ValueError(msg)

            # Clear previous key and set new one
            if self.current_encryption_key:
                SecureMemory.secure_clear(self.current_encryption_key)
            
            self.current_encryption_key = SecureMemory.create_secure_bytes(AES_KEY_SIZE)
            self.current_encryption_key[:] = key_bytes
            
            self.loaded_recipient_var.set(f"{name} ✓ ({fingerprint[:8]}...)")
            self.status_indicator.config(foreground=self.ui_config.get('colors', 'success_color'))

        except Exception as e:
            if self.current_encryption_key:
                SecureMemory.secure_clear(self.current_encryption_key)
            self.current_encryption_key = None
            self.loaded_recipient_var.set(f"{name} (Invalid Key!)")
            self.status_indicator.config(foreground=self.ui_config.get('colors', 'error_color'))
            messagebox.showerror("Load Error", f"Invalid key for {name}: {str(e)}", parent=self.root)

        self.toggle_encrypt_button()

    def setup_decryption_tab(self):
        """Setup message decryption tab"""
        padding = self.ui_config.getint('geometry', 'button_padding')
        text_height = self.ui_config.getint('geometry', 'text_height')
        entry_width = self.ui_config.getint('geometry', 'entry_width')
        
        recipient_frame = ttk.Frame(self.decrypt_tab)
        recipient_frame.pack(fill='x', padx=padding*2, pady=(padding*2, padding))

        ttk.Label(recipient_frame, text="Recipient:").pack(side='left', padx=(0, padding))

        self.decrypt_recipient_var = tk.StringVar()
        self.decrypt_recipient_dropdown = ttk.Combobox(
            recipient_frame,
            textvariable=self.decrypt_recipient_var,
            state="readonly",
            width=entry_width
        )
        self.decrypt_recipient_dropdown.pack(side='left', fill='x', expand=True, padx=padding)

        ttk.Button(recipient_frame, text="Load Key",
                   command=self.load_decrypt_key).pack(side='left', padx=padding)

        status_frame = ttk.Frame(self.decrypt_tab)
        status_frame.pack(fill='x', padx=padding*2, pady=(0, padding))

        ttk.Label(status_frame, text="Key Status:").pack(side='left', padx=(0, padding))

        self.decrypt_key_status = tk.StringVar(value="None")
        self.decrypt_status_indicator = ttk.Label(
            status_frame,
            textvariable=self.decrypt_key_status,
            foreground=self.ui_config.get('colors', 'error_color')
        )
        self.decrypt_status_indicator.pack(side='left', padx=padding)

        input_frame = ttk.LabelFrame(self.decrypt_tab, text="Paste Encrypted Message")
        input_frame.pack(fill='x', padx=padding*2, pady=padding)

        self.encrypted_input = scrolledtext.ScrolledText(input_frame, height=text_height,
                                                        bg=self.ui_config.get('colors', 'entry_bg'),
                                                        fg=self.ui_config.get('colors', 'light_fg'),
                                                        insertbackground=self.ui_config.get('colors', 'light_fg'))
        self.encrypted_input.pack(fill='both', expand=True, padx=padding*2, pady=padding*2)

        output_frame = ttk.LabelFrame(self.decrypt_tab, text="Decrypted Message")
        output_frame.pack(fill='both', expand=True, padx=padding*2, pady=padding)

        self.decrypted_output = scrolledtext.ScrolledText(output_frame, height=text_height,
                                                         bg=self.ui_config.get('colors', 'entry_bg'),
                                                         fg=self.ui_config.get('colors', 'light_fg'),
                                                         insertbackground=self.ui_config.get('colors', 'light_fg'))
        self.decrypted_output.pack(fill='both', expand=True, padx=padding*2, pady=padding*2)
        self.decrypted_output.config(state='disabled')

        button_frame_decrypt = ttk.Frame(self.decrypt_tab)
        button_frame_decrypt.pack(fill='x', padx=padding*2, pady=padding)

        ttk.Button(button_frame_decrypt, text="Decrypt Message",
                   command=self.decrypt_message).pack(side='left', padx=padding)

        ttk.Button(button_frame_decrypt, text="Clear",
                   command=self.clear_decrypt).pack(side='right', padx=padding)

    def load_decrypt_key(self):
        """Load selected recipient's key for decryption"""
        name = self.decrypt_recipient_var.get()
        if not name:
            messagebox.showwarning("No Recipient", "Select a recipient first.", parent=self.root)
            return

        recipient = next((r for r in self.recipients if r["name"] == name), None)
        if not recipient:
            messagebox.showwarning("Not Found", f"No recipient named '{name}'.", parent=self.root)
            return

        try:
            valid, msg, key_bytes, fingerprint = CryptoValidator.validate_base64_key(recipient["key"])
            
            if not valid:
                raise ValueError(msg)

            # Clear previous key and set new one
            if hasattr(self, 'current_decryption_key') and self.current_decryption_key:
                SecureMemory.secure_clear(self.current_decryption_key)
            
            self.current_decryption_key = SecureMemory.create_secure_bytes(AES_KEY_SIZE)
            self.current_decryption_key[:] = key_bytes
            
            self.decrypt_key_status.set(f"{name} ✓ ({fingerprint[:8]}...)")
            self.decrypt_status_indicator.config(foreground=self.ui_config.get('colors', 'success_color'))

        except Exception as e:
            if hasattr(self, 'current_decryption_key') and self.current_decryption_key:
                SecureMemory.secure_clear(self.current_decryption_key)
            self.current_decryption_key = None
            self.decrypt_key_status.set(f"{name} (Invalid Key!)")
            self.decrypt_status_indicator.config(foreground=self.ui_config.get('colors', 'error_color'))
            messagebox.showerror("Load Error", f"Invalid key for {name}: {str(e)}", parent=self.root)

    def encrypt_message(self):
        """Encrypt message with loaded key"""
        if not self.current_encryption_key:
            messagebox.showwarning("No Key", "Load recipient's key first.", parent=self.root)
            return

        message = self.message_input.get("1.0", "end-1c")
        message = InputSanitizer.sanitize_message(message)
        
        if not message:
            messagebox.showwarning("No Message", "Enter a message to encrypt.", parent=self.root)
            return

        try:
            # Generate a random nonce for GCM
            nonce = secrets.token_bytes(GCM_NONCE_SIZE)
            
            # Create cipher object with GCM mode
            cipher = Cipher(
                algorithms.AES(bytes(self.current_encryption_key)),
                modes.GCM(nonce),
                backend=default_backend()
            )

            # Encrypt the message
            encryptor = cipher.encryptor()
            plaintext = message.encode('utf-8')
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Get the authentication tag
            tag = encryptor.tag

            # Combine nonce + ciphertext + tag
            encrypted_data = nonce + ciphertext + tag
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')

            formatted_output = f"-----BEGIN ENCRYPTED MESSAGE-----\n{encrypted_b64}\n-----END ENCRYPTED MESSAGE-----"

            # Display result
            self.encrypted_output.config(state='normal')
            self.encrypted_output.delete('1.0', tk.END)
            self.encrypted_output.insert(tk.END, formatted_output)
            self.encrypted_output.config(state='disabled')

            # Secure cleanup
            SecureMemory.secure_clear(plaintext)

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e), parent=self.root)

    def decrypt_message(self):
        """Decrypt message with loaded key"""
        if not hasattr(self, 'current_decryption_key') or not self.current_decryption_key:
            messagebox.showwarning("No Key", "Load your decryption key first.", parent=self.root)
            return

        encrypted_text_full = self.encrypted_input.get("1.0", tk.END).strip()
        if not encrypted_text_full:
            messagebox.showwarning("No Input", "Paste the encrypted message to decrypt.", parent=self.root)
            return

        try:
            # Extract the base64 payload - only support current format
            if encrypted_text_full.startswith("-----BEGIN ENCRYPTED MESSAGE-----"):
                lines = encrypted_text_full.split('\n')
                encrypted_text = '\n'.join(lines[1:-1]).strip()
            else:
                encrypted_text = encrypted_text_full

            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_text)

            # Split nonce, ciphertext, and tag
            if len(encrypted_data) < (GCM_NONCE_SIZE + GCM_TAG_SIZE):
                raise ValueError("Invalid encrypted data length")
                
            nonce = encrypted_data[:GCM_NONCE_SIZE]
            tag = encrypted_data[-GCM_TAG_SIZE:]
            ciphertext = encrypted_data[GCM_NONCE_SIZE:-GCM_TAG_SIZE]

            # Create cipher object with GCM mode
            cipher = Cipher(
                algorithms.AES(bytes(self.current_decryption_key)),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )

            # Decrypt the message
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Display result
            self.decrypted_output.config(state='normal')
            self.decrypted_output.delete('1.0', tk.END)
            self.decrypted_output.insert(tk.END, plaintext.decode('utf-8'))
            self.decrypted_output.config(state='disabled')

            # Secure cleanup
            SecureMemory.secure_clear(plaintext)

        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt: {str(e)}", parent=self.root)

    def copy_encrypted(self):
        """Copy encrypted message to clipboard"""
        encrypted_text = self.encrypted_output.get("1.0", tk.END).strip()
        if not encrypted_text:
            messagebox.showwarning("No Content", "Nothing to copy.", parent=self.root)
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(encrypted_text)
        messagebox.showinfo("Copied", "Encrypted message copied to clipboard.", parent=self.root)

    def clear_encrypt(self):
        """Clear encryption tab"""
        self.message_input.delete('1.0', tk.END)
        self.encrypted_output.config(state='normal')
        self.encrypted_output.delete('1.0', tk.END)
        self.encrypted_output.config(state='disabled')

    def clear_decrypt(self):
        """Clear decryption tab"""
        self.encrypted_input.delete('1.0', tk.END)
        self.decrypted_output.config(state='normal')
        self.decrypted_output.delete('1.0', tk.END)
        self.decrypted_output.config(state='disabled')
        self.decrypt_recipient_var.set("")
        self.decrypt_key_status.set("None")
        self.decrypt_status_indicator.config(foreground=self.ui_config.get('colors', 'error_color'))




if __name__ == "__main__":
    root = tk.Tk()
    app = E2EMessagingTool(root)
    root.mainloop()

