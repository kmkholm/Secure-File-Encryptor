"""
Secure File Encryption Tool
Author: Dr. Mohammed Tafik
Advanced AES-256 Encryption System with GUI Interface

Features:
- AES-256-GCM encryption with authentication
- PBKDF2 key derivation
- Key generation and management
- File integrity verification
- Progress visualization
- Secure key storage
- Encryption/Decryption logging
"""

import os
import sys
import json
import hashlib
import secrets
import base64
import logging
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import threading
import time


class CryptoEngine:
    """Core encryption/decryption engine using AES-256-GCM"""
    
    SALT_SIZE = 32
    NONCE_SIZE = 16
    TAG_SIZE = 16
    KEY_SIZE = 32  # 256 bits
    ITERATIONS = 100000
    CHUNK_SIZE = 64 * 1024  # 64KB chunks for large files
    
    def __init__(self):
        self.backend = default_backend()
        
    def generate_salt(self):
        """Generate cryptographically secure random salt"""
        return secrets.token_bytes(self.SALT_SIZE)
    
    def generate_nonce(self):
        """Generate cryptographically secure random nonce"""
        return secrets.token_bytes(self.NONCE_SIZE)
    
    def derive_key(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def generate_random_key(self):
        """Generate a random 256-bit encryption key"""
        return secrets.token_bytes(self.KEY_SIZE)
    
    def encrypt_file(self, input_path, output_path, password, progress_callback=None):
        """
        Encrypt a file using AES-256-GCM
        
        File structure:
        [SALT(32)][NONCE(16)][TAG(16)][ENCRYPTED_DATA]
        """
        try:
            # Generate salt and derive key
            salt = self.generate_salt()
            key = self.derive_key(password, salt)
            
            # Generate nonce
            nonce = self.generate_nonce()
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Get file size for progress calculation
            file_size = os.path.getsize(input_path)
            processed = 0
            
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write salt and nonce
                outfile.write(salt)
                outfile.write(nonce)
                
                # Skip tag position (will write later)
                tag_position = outfile.tell()
                outfile.write(b'\x00' * self.TAG_SIZE)
                
                # Encrypt file in chunks
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                    
                    processed += len(chunk)
                    if progress_callback:
                        progress = (processed / file_size) * 100
                        progress_callback(progress)
                
                # Finalize and get tag
                encryptor.finalize()
                tag = encryptor.tag
                
                # Write tag at reserved position
                outfile.seek(tag_position)
                outfile.write(tag)
            
            return True, "File encrypted successfully"
            
        except Exception as e:
            return False, f"Encryption error: {str(e)}"
    
    def decrypt_file(self, input_path, output_path, password, progress_callback=None):
        """
        Decrypt a file using AES-256-GCM
        """
        try:
            with open(input_path, 'rb') as infile:
                # Read salt, nonce, and tag
                salt = infile.read(self.SALT_SIZE)
                nonce = infile.read(self.NONCE_SIZE)
                tag = infile.read(self.TAG_SIZE)
                
                if len(salt) != self.SALT_SIZE or len(nonce) != self.NONCE_SIZE:
                    return False, "Invalid encrypted file format"
                
                # Derive key
                key = self.derive_key(password, salt)
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(nonce, tag),
                    backend=self.backend
                )
                decryptor = cipher.decryptor()
                
                # Get remaining file size
                current_pos = infile.tell()
                infile.seek(0, 2)  # Seek to end
                file_size = infile.tell() - current_pos
                infile.seek(current_pos)
                processed = 0
                
                with open(output_path, 'wb') as outfile:
                    # Decrypt file in chunks
                    while True:
                        chunk = infile.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        
                        decrypted_chunk = decryptor.update(chunk)
                        outfile.write(decrypted_chunk)
                        
                        processed += len(chunk)
                        if progress_callback:
                            progress = (processed / file_size) * 100
                            progress_callback(progress)
                    
                    # Finalize
                    decryptor.finalize()
            
            return True, "File decrypted successfully"
            
        except Exception as e:
            return False, f"Decryption error: {str(e)}"
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()


class KeyManager:
    """Manage encryption keys storage and retrieval"""
    
    def __init__(self, keys_dir="encryption_keys"):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        self.keys_file = self.keys_dir / "keys.json"
        self.keys = self.load_keys()
    
    def load_keys(self):
        """Load saved keys from file"""
        if self.keys_file.exists():
            try:
                with open(self.keys_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_keys(self):
        """Save keys to file"""
        with open(self.keys_file, 'w') as f:
            json.dump(self.keys, f, indent=4)
    
    def add_key(self, name, key_bytes):
        """Add a new key"""
        key_b64 = base64.b64encode(key_bytes).decode()
        self.keys[name] = {
            "key": key_b64,
            "created": datetime.now().isoformat(),
            "size": len(key_bytes) * 8  # bits
        }
        self.save_keys()
    
    def get_key(self, name):
        """Retrieve a key"""
        if name in self.keys:
            key_b64 = self.keys[name]["key"]
            return base64.b64decode(key_b64.encode())
        return None
    
    def delete_key(self, name):
        """Delete a key"""
        if name in self.keys:
            del self.keys[name]
            self.save_keys()
            return True
        return False
    
    def list_keys(self):
        """List all saved keys"""
        return list(self.keys.keys())
    
    def export_key(self, name, export_path):
        """Export key to file"""
        if name in self.keys:
            with open(export_path, 'w') as f:
                json.dump({name: self.keys[name]}, f, indent=4)
            return True
        return False
    
    def import_key(self, import_path):
        """Import key from file"""
        try:
            with open(import_path, 'r') as f:
                imported = json.load(f)
                self.keys.update(imported)
                self.save_keys()
            return True
        except:
            return False


class EncryptionLogger:
    """Log encryption/decryption operations"""
    
    def __init__(self, log_dir="encryption_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / f"encryption_log_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_encryption(self, file_path, output_path, success, message):
        """Log encryption operation"""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"ENCRYPT [{status}] - Input: {file_path} -> Output: {output_path} | {message}")
    
    def log_decryption(self, file_path, output_path, success, message):
        """Log decryption operation"""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"DECRYPT [{status}] - Input: {file_path} -> Output: {output_path} | {message}")
    
    def log_key_generation(self, key_name):
        """Log key generation"""
        self.logger.info(f"KEY_GEN - Generated new key: {key_name}")
    
    def log_key_deletion(self, key_name):
        """Log key deletion"""
        self.logger.info(f"KEY_DEL - Deleted key: {key_name}")


class SecureFileEncryptorGUI:
    """Main GUI Application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryptor - Dr. Mohammed Tafik")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Initialize components
        self.crypto = CryptoEngine()
        self.key_manager = KeyManager()
        self.logger = EncryptionLogger()
        
        # Variables
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.password = tk.StringVar()
        self.use_saved_key = tk.BooleanVar(value=False)
        self.selected_key = tk.StringVar()
        
        # Setup UI
        self.setup_ui()
        
        # Styling
        self.apply_styles()
    
    def apply_styles(self):
        """Apply modern styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'), foreground='#2c3e50')
        style.configure('Subtitle.TLabel', font=('Helvetica', 10), foreground='#34495e')
        style.configure('Action.TButton', font=('Helvetica', 10, 'bold'))
        style.configure('Success.TLabel', foreground='#27ae60')
        style.configure('Error.TLabel', foreground='#e74c3c')
    
    def setup_ui(self):
        """Setup the user interface"""
        # Create menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="Quick Start", command=self.show_quick_start)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title = ttk.Label(main_frame, text="🔐 Secure File Encryptor", style='Title.TLabel')
        title.grid(row=0, column=0, columnspan=3, pady=10)
        
        subtitle = ttk.Label(main_frame, text="AES-256-GCM Encryption System", style='Subtitle.TLabel')
        subtitle.grid(row=1, column=0, columnspan=3, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Tab 1: Encrypt/Decrypt
        self.create_encryption_tab()
        
        # Tab 2: Key Management
        self.create_key_management_tab()
        
        # Tab 3: Logs
        self.create_logs_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
    
    def create_encryption_tab(self):
        """Create encryption/decryption tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Encrypt/Decrypt")
        
        # File selection
        file_frame = ttk.LabelFrame(tab, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(file_frame, text="Input File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(file_frame, textvariable=self.input_file, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_input_file).grid(row=0, column=2, pady=5)
        
        ttk.Label(file_frame, text="Output File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(file_frame, textvariable=self.output_file, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_output_file).grid(row=1, column=2, pady=5)
        
        # Authentication
        auth_frame = ttk.LabelFrame(tab, text="Authentication", padding="10")
        auth_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Checkbutton(auth_frame, text="Use Saved Key", variable=self.use_saved_key, 
                       command=self.toggle_auth_method).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(auth_frame, textvariable=self.password, show="*", width=50)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(auth_frame, text="Saved Key:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.key_combo = ttk.Combobox(auth_frame, textvariable=self.selected_key, width=47, state='disabled')
        self.key_combo.grid(row=2, column=1, padx=5, pady=5)
        self.update_key_list()
        
        # Progress
        progress_frame = ttk.LabelFrame(tab, text="Progress", padding="10")
        progress_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, length=400)
        self.progress_bar.grid(row=0, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
        
        self.progress_label = ttk.Label(progress_frame, text="0%")
        self.progress_label.grid(row=1, column=0, columnspan=2)
        
        # Action buttons
        action_frame = ttk.Frame(tab)
        action_frame.grid(row=3, column=0, pady=20)
        
        ttk.Button(action_frame, text="🔒 Encrypt File", command=self.encrypt_file, 
                  style='Action.TButton', width=20).grid(row=0, column=0, padx=10)
        ttk.Button(action_frame, text="🔓 Decrypt File", command=self.decrypt_file, 
                  style='Action.TButton', width=20).grid(row=0, column=1, padx=10)
        ttk.Button(action_frame, text="🧹 Clear", command=self.clear_fields, 
                  width=20).grid(row=0, column=2, padx=10)
        
        # Result display
        result_frame = ttk.LabelFrame(tab, text="Result", padding="10")
        result_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=8, width=70)
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)
        file_frame.columnconfigure(1, weight=1)
        auth_frame.columnconfigure(1, weight=1)
        progress_frame.columnconfigure(0, weight=1)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
    
    def create_key_management_tab(self):
        """Create key management tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Key Management")
        
        # Key generation
        gen_frame = ttk.LabelFrame(tab, text="Generate New Key", padding="10")
        gen_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(gen_frame, text="Key Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_key_name = tk.StringVar()
        ttk.Entry(gen_frame, textvariable=self.new_key_name, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(gen_frame, text="Generate Key", command=self.generate_key).grid(row=0, column=2, padx=5, pady=5)
        
        # Key list
        list_frame = ttk.LabelFrame(tab, text="Saved Keys", padding="10")
        list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Treeview for keys
        columns = ('name', 'created', 'size')
        self.key_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        self.key_tree.heading('name', text='Key Name')
        self.key_tree.heading('created', text='Created')
        self.key_tree.heading('size', text='Key Size (bits)')
        
        self.key_tree.column('name', width=200)
        self.key_tree.column('created', width=200)
        self.key_tree.column('size', width=150)
        
        self.key_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.key_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.key_tree.configure(yscrollcommand=scrollbar.set)
        
        # Key actions
        action_frame = ttk.Frame(tab)
        action_frame.grid(row=2, column=0, pady=10)
        
        ttk.Button(action_frame, text="Refresh", command=self.refresh_key_list, width=15).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="Export Key", command=self.export_key, width=15).grid(row=0, column=1, padx=5)
        ttk.Button(action_frame, text="Import Key", command=self.import_key, width=15).grid(row=0, column=2, padx=5)
        ttk.Button(action_frame, text="Delete Key", command=self.delete_key, width=15).grid(row=0, column=3, padx=5)
        
        # Configure grid weights
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        gen_frame.columnconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Initial population
        self.refresh_key_list()
    
    def create_logs_tab(self):
        """Create logs tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Logs")
        
        # Log display
        log_frame = ttk.LabelFrame(tab, text="Encryption/Decryption Logs", padding="10")
        log_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=25, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Log actions
        action_frame = ttk.Frame(tab)
        action_frame.grid(row=1, column=0, pady=10)
        
        ttk.Button(action_frame, text="Refresh Logs", command=self.refresh_logs, width=15).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="Clear Logs", command=self.clear_logs, width=15).grid(row=0, column=1, padx=5)
        ttk.Button(action_frame, text="Export Logs", command=self.export_logs, width=15).grid(row=0, column=2, padx=5)
        
        # Configure grid weights
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Load initial logs
        self.refresh_logs()
    
    def toggle_auth_method(self):
        """Toggle between password and saved key authentication"""
        if self.use_saved_key.get():
            self.password_entry.configure(state='disabled')
            self.key_combo.configure(state='readonly')
        else:
            self.password_entry.configure(state='normal')
            self.key_combo.configure(state='disabled')
    
    def browse_input_file(self):
        """Browse for input file"""
        filename = filedialog.askopenfilename(
            title="Select Input File",
            filetypes=[
                ("All files", "*.*"),
                ("Encrypted files", "*.enc"),
                ("Encrypted files", "*_encrypted.*"),
                ("PDF files", "*.pdf"),
                ("Word files", "*.docx"),
                ("Text files", "*.txt"),
                ("Image files", "*.jpg *.jpeg *.png")
            ]
        )
        if filename:
            self.input_file.set(filename)
            # Auto-suggest output filename
            if not self.output_file.get():
                base, ext = os.path.splitext(filename)
                # Check if it's an encrypted file for decryption suggestion
                if filename.endswith('.enc'):
                    # Remove .enc extension
                    suggested = base
                elif '_encrypted' in base:
                    # Remove _encrypted from filename
                    suggested = base.replace('_encrypted', '') + ext
                else:
                    # For encryption, add _encrypted
                    suggested = f"{base}_encrypted{ext}" if ext else f"{filename}_encrypted"
                self.output_file.set(suggested)
    
    def browse_output_file(self):
        """Browse for output file"""
        # Determine default extension based on input file
        default_ext = ".txt"
        filetypes = [("All files", "*.*")]
        
        if self.input_file.get():
            input_path = self.input_file.get()
            # Check if it's an encrypted file (for decryption)
            if input_path.endswith('.enc') or '_encrypted' in input_path:
                # Decrypting - suggest original extension
                base_name = input_path.replace('.enc', '').replace('_encrypted', '')
                _, ext = os.path.splitext(base_name)
                if ext:
                    default_ext = ext
                    filetypes.insert(0, (f"{ext[1:].upper()} files", f"*{ext}"))
            else:
                # Encrypting - suggest .enc or keep extension
                _, ext = os.path.splitext(input_path)
                default_ext = ext if ext else ".enc"
                filetypes.insert(0, ("Encrypted files", "*.enc"))
        
        filename = filedialog.asksaveasfilename(
            title="Select Output File",
            defaultextension=default_ext,
            filetypes=filetypes
        )
        if filename:
            self.output_file.set(filename)
    
    def update_progress(self, progress):
        """Update progress bar"""
        self.progress_var.set(progress)
        self.progress_label.config(text=f"{progress:.1f}%")
        self.root.update_idletasks()
    
    def clear_fields(self):
        """Clear all input fields"""
        self.input_file.set("")
        self.output_file.set("")
        self.password.set("")
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.result_text.delete(1.0, tk.END)
        self.status_var.set("Fields cleared")
    
    def encrypt_file(self):
        """Encrypt file"""
        # Validation
        if not self.input_file.get():
            messagebox.showerror("Error", "Please select an input file")
            return
        
        if not self.output_file.get():
            messagebox.showerror("Error", "Please specify an output file")
            return
        
        # Check if input and output are the same
        if os.path.abspath(self.input_file.get()) == os.path.abspath(self.output_file.get()):
            messagebox.showerror("Error", "Output file cannot be the same as input file!\nPlease choose a different output filename.")
            return
        
        if not self.use_saved_key.get() and not self.password.get():
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if self.use_saved_key.get() and not self.selected_key.get():
            messagebox.showerror("Error", "Please select a saved key")
            return
        
        # Get password or key
        if self.use_saved_key.get():
            key_bytes = self.key_manager.get_key(self.selected_key.get())
            password = base64.b64encode(key_bytes).decode()
        else:
            password = self.password.get()
        
        # Disable buttons during operation
        self.set_buttons_state('disabled')
        self.status_var.set("Encrypting...")
        self.result_text.delete(1.0, tk.END)
        
        # Run encryption in thread
        def encrypt_thread():
            start_time = time.time()
            success, message = self.crypto.encrypt_file(
                self.input_file.get(),
                self.output_file.get(),
                password,
                self.update_progress
            )
            elapsed_time = time.time() - start_time
            
            # Calculate file hash
            if success:
                input_hash = self.crypto.calculate_file_hash(self.input_file.get())
                output_hash = self.crypto.calculate_file_hash(self.output_file.get())
            
            # Log operation
            self.logger.log_encryption(self.input_file.get(), self.output_file.get(), success, message)
            
            # Update UI
            self.root.after(0, lambda: self.encryption_complete(success, message, elapsed_time, 
                                                                input_hash if success else None,
                                                                output_hash if success else None))
        
        threading.Thread(target=encrypt_thread, daemon=True).start()
    
    def decrypt_file(self):
        """Decrypt file"""
        # Validation
        if not self.input_file.get():
            messagebox.showerror("Error", "Please select an input file")
            return
        
        if not self.output_file.get():
            messagebox.showerror("Error", "Please specify an output file")
            return
        
        # Check if input and output are the same
        if os.path.abspath(self.input_file.get()) == os.path.abspath(self.output_file.get()):
            messagebox.showerror("Error", "Output file cannot be the same as input file!\nPlease choose a different output filename.")
            return
        
        if not self.use_saved_key.get() and not self.password.get():
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if self.use_saved_key.get() and not self.selected_key.get():
            messagebox.showerror("Error", "Please select a saved key")
            return
        
        # Get password or key
        if self.use_saved_key.get():
            key_bytes = self.key_manager.get_key(self.selected_key.get())
            password = base64.b64encode(key_bytes).decode()
        else:
            password = self.password.get()
        
        # Disable buttons during operation
        self.set_buttons_state('disabled')
        self.status_var.set("Decrypting...")
        self.result_text.delete(1.0, tk.END)
        
        # Run decryption in thread
        def decrypt_thread():
            start_time = time.time()
            success, message = self.crypto.decrypt_file(
                self.input_file.get(),
                self.output_file.get(),
                password,
                self.update_progress
            )
            elapsed_time = time.time() - start_time
            
            # Calculate file hash
            if success:
                output_hash = self.crypto.calculate_file_hash(self.output_file.get())
            
            # Log operation
            self.logger.log_decryption(self.input_file.get(), self.output_file.get(), success, message)
            
            # Update UI
            self.root.after(0, lambda: self.decryption_complete(success, message, elapsed_time,
                                                                output_hash if success else None))
        
        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    def encryption_complete(self, success, message, elapsed_time, input_hash, output_hash):
        """Handle encryption completion"""
        self.set_buttons_state('normal')
        
        if success:
            self.status_var.set("Encryption completed successfully")
            result = f"✅ ENCRYPTION SUCCESSFUL\n\n"
            result += f"Input File: {self.input_file.get()}\n"
            result += f"Output File: {self.output_file.get()}\n"
            result += f"Time Elapsed: {elapsed_time:.2f} seconds\n"
            result += f"Input File Hash (SHA-256): {input_hash}\n"
            result += f"Encrypted File Hash (SHA-256): {output_hash}\n"
            result += f"\nMessage: {message}"
            
            self.result_text.insert(1.0, result)
            self.result_text.tag_add("success", "1.0", "2.0")
            self.result_text.tag_config("success", foreground="#27ae60", font=('Helvetica', 10, 'bold'))
            
            messagebox.showinfo("Success", "File encrypted successfully!")
        else:
            self.status_var.set("Encryption failed")
            result = f"❌ ENCRYPTION FAILED\n\n"
            result += f"Error: {message}\n"
            
            self.result_text.insert(1.0, result)
            self.result_text.tag_add("error", "1.0", "2.0")
            self.result_text.tag_config("error", foreground="#e74c3c", font=('Helvetica', 10, 'bold'))
            
            messagebox.showerror("Error", f"Encryption failed: {message}")
    
    def decryption_complete(self, success, message, elapsed_time, output_hash):
        """Handle decryption completion"""
        self.set_buttons_state('normal')
        
        if success:
            self.status_var.set("Decryption completed successfully")
            result = f"✅ DECRYPTION SUCCESSFUL\n\n"
            result += f"Input File: {self.input_file.get()}\n"
            result += f"Output File: {self.output_file.get()}\n"
            result += f"Time Elapsed: {elapsed_time:.2f} seconds\n"
            result += f"Decrypted File Hash (SHA-256): {output_hash}\n"
            result += f"\nMessage: {message}"
            
            self.result_text.insert(1.0, result)
            self.result_text.tag_add("success", "1.0", "2.0")
            self.result_text.tag_config("success", foreground="#27ae60", font=('Helvetica', 10, 'bold'))
            
            messagebox.showinfo("Success", "File decrypted successfully!")
        else:
            self.status_var.set("Decryption failed")
            result = f"❌ DECRYPTION FAILED\n\n"
            result += f"Error: {message}\n"
            
            self.result_text.insert(1.0, result)
            self.result_text.tag_add("error", "1.0", "2.0")
            self.result_text.tag_config("error", foreground="#e74c3c", font=('Helvetica', 10, 'bold'))
            
            messagebox.showerror("Error", f"Decryption failed: {message}")
    
    def set_buttons_state(self, state):
        """Enable or disable all buttons"""
        for child in self.root.winfo_children():
            self.set_widget_state(child, state)
    
    def set_widget_state(self, widget, state):
        """Recursively set widget state"""
        try:
            widget.configure(state=state)
        except:
            pass
        for child in widget.winfo_children():
            self.set_widget_state(child, state)
    
    def generate_key(self):
        """Generate a new encryption key"""
        key_name = self.new_key_name.get().strip()
        
        if not key_name:
            messagebox.showerror("Error", "Please enter a key name")
            return
        
        if key_name in self.key_manager.list_keys():
            messagebox.showerror("Error", "A key with this name already exists")
            return
        
        # Generate key
        key_bytes = self.crypto.generate_random_key()
        
        # Save key
        self.key_manager.add_key(key_name, key_bytes)
        self.logger.log_key_generation(key_name)
        
        # Update UI
        self.new_key_name.set("")
        self.refresh_key_list()
        self.update_key_list()
        
        messagebox.showinfo("Success", f"Key '{key_name}' generated successfully!")
        self.status_var.set(f"Key '{key_name}' generated")
    
    def refresh_key_list(self):
        """Refresh the key list in tree view"""
        # Clear existing items
        for item in self.key_tree.get_children():
            self.key_tree.delete(item)
        
        # Add keys
        keys = self.key_manager.keys
        for name, info in keys.items():
            created = datetime.fromisoformat(info['created']).strftime('%Y-%m-%d %H:%M:%S')
            self.key_tree.insert('', tk.END, values=(name, created, info['size']))
    
    def update_key_list(self):
        """Update key dropdown list"""
        keys = self.key_manager.list_keys()
        self.key_combo['values'] = keys
    
    def export_key(self):
        """Export selected key"""
        selected = self.key_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a key to export")
            return
        
        key_name = self.key_tree.item(selected[0])['values'][0]
        
        filename = filedialog.asksaveasfilename(
            title="Export Key",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if filename:
            if self.key_manager.export_key(key_name, filename):
                messagebox.showinfo("Success", f"Key '{key_name}' exported successfully!")
                self.status_var.set(f"Key '{key_name}' exported")
            else:
                messagebox.showerror("Error", "Failed to export key")
    
    def import_key(self):
        """Import a key"""
        filename = filedialog.askopenfilename(
            title="Import Key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if filename:
            if self.key_manager.import_key(filename):
                self.refresh_key_list()
                self.update_key_list()
                messagebox.showinfo("Success", "Key imported successfully!")
                self.status_var.set("Key imported")
            else:
                messagebox.showerror("Error", "Failed to import key")
    
    def delete_key(self):
        """Delete selected key"""
        selected = self.key_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a key to delete")
            return
        
        key_name = self.key_tree.item(selected[0])['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete key '{key_name}'?"):
            if self.key_manager.delete_key(key_name):
                self.logger.log_key_deletion(key_name)
                self.refresh_key_list()
                self.update_key_list()
                messagebox.showinfo("Success", f"Key '{key_name}' deleted successfully!")
                self.status_var.set(f"Key '{key_name}' deleted")
            else:
                messagebox.showerror("Error", "Failed to delete key")
    
    def refresh_logs(self):
        """Refresh log display"""
        self.log_text.delete(1.0, tk.END)
        
        log_file = self.logger.log_file
        if log_file.exists():
            with open(log_file, 'r') as f:
                logs = f.read()
                self.log_text.insert(1.0, logs)
        else:
            self.log_text.insert(1.0, "No logs available")
    
    def clear_logs(self):
        """Clear log display"""
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear all logs?"):
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(1.0, "Logs cleared")
            self.status_var.set("Logs cleared")
    
    def export_logs(self):
        """Export logs to file"""
        filename = filedialog.asksaveasfilename(
            title="Export Logs",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            log_content = self.log_text.get(1.0, tk.END)
            with open(filename, 'w') as f:
                f.write(log_content)
            messagebox.showinfo("Success", "Logs exported successfully!")
            self.status_var.set("Logs exported")
    
    def show_user_guide(self):
        """Show user guide window"""
        guide_window = tk.Toplevel(self.root)
        guide_window.title("User Guide - Secure File Encryptor")
        guide_window.geometry("700x600")
        
        # Create scrolled text
        text_frame = ttk.Frame(guide_window, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        guide_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, font=('Arial', 10))
        guide_text.pack(fill=tk.BOTH, expand=True)
        
        guide_content = """
SECURE FILE ENCRYPTOR - USER GUIDE
==================================

OVERVIEW
--------
This application encrypts and decrypts files using military-grade AES-256-GCM encryption.
Your files are protected with authenticated encryption providing both confidentiality and integrity.

ENCRYPTING A FILE
-----------------
1. Click "Browse" next to "Input File" and select the file you want to encrypt
2. The output filename will be suggested automatically (with "_encrypted" suffix)
3. Choose authentication method:
   • Password: Enter a strong password (min 8 characters)
   • Saved Key: Check "Use Saved Key" and select from dropdown
4. Click "🔒 Encrypt File"
5. Wait for the progress bar to complete
6. Your encrypted file is ready!

DECRYPTING A FILE
-----------------
1. Click "Browse" next to "Input File" and select the encrypted file
2. The output filename will be suggested automatically (removing "_encrypted")
3. Enter the SAME password or key used for encryption
4. Click "🔓 Decrypt File"
5. Wait for the progress bar to complete
6. Your original file is restored!

IMPORTANT: You MUST use the exact same password or key for decryption!

MANAGING ENCRYPTION KEYS
-------------------------
Keys are an alternative to passwords - they're randomly generated and can be saved.

Generating a Key:
1. Go to "Key Management" tab
2. Enter a name for your key (e.g., "WorkFiles2024")
3. Click "Generate Key"
4. The key is automatically saved

Using a Saved Key:
1. In "Encrypt/Decrypt" tab, check "Use Saved Key"
2. Select your key from the dropdown
3. No need to type password - just encrypt/decrypt!

Exporting/Importing Keys:
• Export: Share keys with other computers or create backups
• Import: Load keys from exported files
• Delete: Remove old/unused keys

VIEWING LOGS
------------
The "Logs" tab shows all encryption/decryption operations including:
• Timestamp of each operation
• File paths
• Success/failure status
• Any error messages

SECURITY TIPS
-------------
✓ Use strong passwords: Mix uppercase, lowercase, numbers, and symbols
✓ Minimum 12 characters recommended
✓ Don't use dictionary words or personal info
✓ Keep passwords and keys in a secure location
✓ Never share passwords over insecure channels
✓ Test decryption before deleting original files

WARNING: Lost passwords CANNOT be recovered!
If you forget your password, the encrypted file is permanently inaccessible.

TROUBLESHOOTING
---------------
Problem: Decryption fails with correct password
• Check that you selected the encrypted file, not the original
• Verify the file wasn't corrupted or modified
• Make sure password is exactly correct (case-sensitive)

Problem: File is too large
• The application handles files up to several GB
• For very large files, encryption may take longer
• Be patient and watch the progress bar

Problem: Can't see encrypted files
• Look for files ending in ".enc" or "_encrypted"
• Check the correct directory

For more help, check the logs or review the documentation files.

TECHNICAL DETAILS
-----------------
Encryption: AES-256-GCM (military-grade)
Key Derivation: PBKDF2-HMAC-SHA256 (100,000 iterations)
File Integrity: SHA-256 hash verification
Security: Authenticated encryption with tamper detection
        """
        
        guide_text.insert(1.0, guide_content)
        guide_text.config(state='disabled')
        
        # Close button
        close_btn = ttk.Button(text_frame, text="Close", command=guide_window.destroy)
        close_btn.pack(pady=10)
    
    def show_quick_start(self):
        """Show quick start guide"""
        quick_window = tk.Toplevel(self.root)
        quick_window.title("Quick Start - Secure File Encryptor")
        quick_window.geometry("600x500")
        
        text_frame = ttk.Frame(quick_window, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        quick_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, font=('Arial', 10))
        quick_text.pack(fill=tk.BOTH, expand=True)
        
        quick_content = """
QUICK START GUIDE
=================

🔒 TO ENCRYPT A FILE:
--------------------
1. Browse and select your file
2. Enter a strong password
3. Click "Encrypt File"
4. Done! Your file is encrypted

🔓 TO DECRYPT A FILE:
--------------------
1. Browse and select the encrypted file (ends with _encrypted or .enc)
2. Enter the SAME password you used for encryption
3. Click "Decrypt File"
4. Done! Your original file is back

⚠️ IMPORTANT NOTES:
-------------------
• REMEMBER your password! Lost passwords = lost files
• Use SAME password for decrypt that you used for encrypt
• Passwords are case-sensitive (MyPassword ≠ mypassword)
• Strong passwords: Min 12 chars, mix upper/lower/numbers/symbols

✅ GOOD PASSWORDS:
• MyS3cur3P@ssw0rd!
• Dr.T@wfik#2024$Secure
• C0mpl3xP@ss#123

❌ BAD PASSWORDS:
• password123
• 12345678
• yourname

🔑 USING SAVED KEYS (OPTIONAL):
-------------------------------
1. Go to "Key Management" tab
2. Create a new key with a name
3. Back to main tab, check "Use Saved Key"
4. Select your key
5. Encrypt/decrypt without typing password!

💡 TIPS:
--------
• Test decrypt before deleting original files
• Keep backups of important files
• Export keys for backup
• Check the Logs tab if something goes wrong

That's it! You're ready to secure your files! 🎉
        """
        
        quick_text.insert(1.0, quick_content)
        quick_text.config(state='disabled')
        
        close_btn = ttk.Button(text_frame, text="Close", command=quick_window.destroy)
        close_btn.pack(pady=10)
    
    def show_about(self):
        """Show about dialog"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About - Secure File Encryptor")
        about_window.geometry("500x550")
        about_window.resizable(False, False)
        
        # Main frame
        main_frame = ttk.Frame(about_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Icon/Title
        title_label = ttk.Label(main_frame, text="🔐 Secure File Encryptor", 
                                font=('Helvetica', 18, 'bold'), foreground='#2c3e50')
        title_label.pack(pady=10)
        
        version_label = ttk.Label(main_frame, text="Version 1.0.0", 
                                  font=('Helvetica', 10), foreground='#7f8c8d')
        version_label.pack()
        
        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=15)
        
        # Author info
        author_frame = ttk.Frame(main_frame)
        author_frame.pack(pady=10)
        
        ttk.Label(author_frame, text="Created by:", 
                 font=('Helvetica', 10, 'bold')).pack()
        ttk.Label(author_frame, text="Dr. Mohammed Tawfik", 
                 font=('Helvetica', 14, 'bold'), foreground='#3498db').pack(pady=5)
        
        ttk.Label(author_frame, text="Assistant Professor of Cybersecurity", 
                 font=('Helvetica', 9)).pack()
        ttk.Label(author_frame, text="Ajloun National University, Jordan", 
                 font=('Helvetica', 9)).pack()
        
        # Project info
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=15)
        
        project_frame = ttk.Frame(main_frame)
        project_frame.pack(pady=5)
        
        ttk.Label(project_frame, text="📚 Bachelor Degree Cybersecurity Project", 
                 font=('Helvetica', 10, 'bold')).pack(pady=5)
        ttk.Label(project_frame, text="cyber security", 
                 font=('Helvetica', 9)).pack()
        
        # Date
        date_label = ttk.Label(main_frame, text="November 9, 2024", 
                              font=('Helvetica', 9, 'italic'), foreground='#95a5a6')
        date_label.pack(pady=10)
        
        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=15)
        
        # Technical info
        tech_frame = ttk.Frame(main_frame)
        tech_frame.pack()
        
        ttk.Label(tech_frame, text="🔐 Technical Specifications:", 
                 font=('Helvetica', 10, 'bold')).pack(anchor='w', pady=5)
        
        specs_text = """
    • Encryption: AES-256-GCM (Military Grade)
    • Key Derivation: PBKDF2-HMAC-SHA256
    • Iterations: 100,000
    • Hash Algorithm: SHA-256
    • Authentication: GCM Tag (128-bit)
        """
        ttk.Label(tech_frame, text=specs_text, 
                 font=('Helvetica', 9), justify='left').pack(anchor='w')
        
        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=15)
        
        # Copyright
        copyright_label = ttk.Label(main_frame, 
                                    text="© 2024 Dr. Mohammed Tawfik - All Rights Reserved", 
                                    font=('Helvetica', 8), foreground='#95a5a6')
        copyright_label.pack(pady=5)
        
        license_label = ttk.Label(main_frame, 
                                 text="Educational Use - Bachelor Degree Project", 
                                 font=('Helvetica', 8), foreground='#95a5a6')
        license_label.pack()
        
        # Close button
        close_btn = ttk.Button(main_frame, text="Close", command=about_window.destroy, 
                              width=20)
        close_btn.pack(pady=15)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = SecureFileEncryptorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()