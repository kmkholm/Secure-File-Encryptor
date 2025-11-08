# 🔐 Secure File Encryptor

**Author:** Dr. Mohammed Tafik  
**Bachelor Degree Cybersecurity Project**

A professional-grade file encryption/decryption tool implementing AES-256-GCM encryption with a modern GUI interface.

---

## 📋 Features

### Core Functionality
- **AES-256-GCM Encryption**: Military-grade encryption with authenticated encryption
- **PBKDF2 Key Derivation**: Secure password-based key derivation (100,000 iterations)
- **Chunk Processing**: Efficient handling of large files (64KB chunks)
- **File Integrity**: SHA-256 hash verification for encrypted/decrypted files
- **Progress Visualization**: Real-time progress tracking with percentage display

### Key Management
- **Key Generation**: Cryptographically secure random key generation (256-bit)
- **Key Storage**: Secure key storage with JSON-based persistence
- **Key Import/Export**: Share keys securely between systems
- **Key Deletion**: Manage stored keys with proper logging

### User Interface
- **Modern GUI**: Clean, professional Tkinter interface
- **Tabbed Layout**: Organized interface with Encrypt/Decrypt, Key Management, and Logs tabs
- **File Browser**: Easy file selection with auto-suggestion for output files
- **Authentication Options**: Support for both password-based and key-based encryption
- **Result Display**: Detailed operation results with color-coded success/error messages

### Logging & Monitoring
- **Operation Logging**: Complete audit trail of all encryption/decryption operations
- **Log Viewer**: Built-in log viewer with refresh and export capabilities
- **Timestamp Recording**: Precise timestamps for all operations
- **Performance Metrics**: Time elapsed for each operation

---

## 🛠️ Technical Specifications

### Encryption Details
- **Algorithm**: AES-256 in GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 128 bits (16 bytes)
- **Salt Size**: 256 bits (32 bytes)
- **Tag Size**: 128 bits (16 bytes) for authentication
- **KDF**: PBKDF2-HMAC-SHA256 with 100,000 iterations

### File Structure
Encrypted files follow this structure:
```
[SALT(32 bytes)][NONCE(16 bytes)][TAG(16 bytes)][ENCRYPTED_DATA]
```

### Security Features
1. **Authenticated Encryption**: GCM mode provides both confidentiality and authenticity
2. **Salt Randomization**: Unique salt for each encryption operation
3. **Nonce Randomization**: Unique nonce prevents replay attacks
4. **Key Derivation**: PBKDF2 protects against dictionary attacks
5. **Secure Random**: Uses cryptographically secure random number generation

---

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install cryptography
```

### Step 2: Run the Application

```bash
python secure_file_encryptor.py
```

---

## 📖 Usage Guide

### 1. Encrypting a File

#### Using Password:
1. Click **"Browse"** next to "Input File" and select the file to encrypt
2. Click **"Browse"** next to "Output File" and specify where to save the encrypted file
3. Enter a strong password in the "Password" field
4. Click **"🔒 Encrypt File"**
5. Wait for the progress bar to complete
6. Review the results showing file hashes and operation time

#### Using Saved Key:
1. First, generate a key in the "Key Management" tab
2. In the "Encrypt/Decrypt" tab, check "Use Saved Key"
3. Select your saved key from the dropdown
4. Select input and output files
5. Click **"🔒 Encrypt File"**

### 2. Decrypting a File

1. Click **"Browse"** next to "Input File" and select the encrypted file
2. Click **"Browse"** next to "Output File" and specify where to save the decrypted file
3. Enter the **same password** used for encryption (or select the same saved key)
4. Click **"🔓 Decrypt File"**
5. Wait for the progress bar to complete
6. Review the results

⚠️ **Important**: Use the exact same password or key that was used for encryption!

### 3. Key Management

#### Generating a Key:
1. Navigate to the "Key Management" tab
2. Enter a name for your key (e.g., "ProjectKey2024")
3. Click **"Generate Key"**
4. The key will be saved automatically and appear in the list

#### Exporting a Key:
1. Select a key from the list
2. Click **"Export Key"**
3. Choose a location and filename
4. The key will be saved as a .key file

#### Importing a Key:
1. Click **"Import Key"**
2. Select a .key file
3. The key will be added to your saved keys

#### Deleting a Key:
1. Select a key from the list
2. Click **"Delete Key"**
3. Confirm the deletion

### 4. Viewing Logs

1. Navigate to the "Logs" tab
2. View all encryption/decryption operations
3. Click **"Refresh Logs"** to update
4. Click **"Export Logs"** to save logs to a file

---

## 🔬 Project Structure

```
secure_file_encryptor/
├── secure_file_encryptor.py   # Main application
├── requirements.txt            # Python dependencies
├── README.md                   # Documentation
├── encryption_keys/            # Directory for saved keys (auto-created)
│   └── keys.json              # Stored encryption keys
└── encryption_logs/            # Directory for operation logs (auto-created)
    └── encryption_log_*.log   # Daily log files
```

---

## 🧪 Testing the Application

### Test 1: Basic Encryption/Decryption
1. Create a test text file with some content
2. Encrypt it using a password
3. Decrypt it using the same password
4. Verify the decrypted content matches the original

### Test 2: Large File Handling
1. Test with a file larger than 100MB
2. Observe the progress bar working correctly
3. Verify successful encryption/decryption

### Test 3: Key Management
1. Generate multiple keys with different names
2. Export a key and import it back
3. Use a saved key for encryption
4. Verify the key-based encryption works

### Test 4: Error Handling
1. Try to decrypt with wrong password (should fail)
2. Try to encrypt without selecting a file (should show error)
3. Try to use a non-existent key (should show error)

---

## 🔐 Security Best Practices

### Password Guidelines
- Use passwords with at least 12 characters
- Include uppercase, lowercase, numbers, and special characters
- Avoid dictionary words or personal information
- Don't reuse passwords from other services

### Key Management
- Store exported keys in a secure location
- Don't share keys over insecure channels (email, chat)
- Use unique keys for different purposes
- Regularly rotate encryption keys

### General Security
- Keep the application and dependencies updated
- Don't encrypt files on shared/public computers
- Securely delete original files after encryption (if needed)
- Backup encryption keys in a secure location

---

## 📊 Performance Benchmarks

Typical performance on modern hardware:

| File Size | Encryption Time | Decryption Time |
|-----------|----------------|----------------|
| 10 MB     | ~0.5 seconds   | ~0.4 seconds   |
| 100 MB    | ~3 seconds     | ~2.5 seconds   |
| 1 GB      | ~25 seconds    | ~22 seconds    |

*Note: Performance varies based on hardware specifications*

---

## 🐛 Troubleshooting

### Issue: "Module 'cryptography' not found"
**Solution**: Install the cryptography library:
```bash
pip install cryptography
```

### Issue: "Permission denied" when encrypting
**Solution**: Ensure you have write permissions to the output directory

### Issue: Decryption fails with correct password
**Solution**: 
- Verify the encrypted file wasn't corrupted
- Ensure you're using the exact same password (case-sensitive)
- Check that the file was encrypted with this tool

### Issue: GUI doesn't appear
**Solution**:
- Ensure Tkinter is installed (usually comes with Python)
- On Linux, install: `sudo apt-get install python3-tk`

---

## 📚 Educational Value

This project demonstrates:

1. **Cryptography Concepts**:
   - Symmetric encryption (AES)
   - Authenticated encryption (GCM mode)
   - Key derivation functions (PBKDF2)
   - Cryptographic hashing (SHA-256)

2. **Software Development**:
   - GUI programming with Tkinter
   - Multi-threading for responsive UI
   - File I/O operations
   - Error handling and validation

3. **Security Practices**:
   - Secure random number generation
   - Salt and nonce usage
   - Key management
   - Audit logging

4. **Python Skills**:
   - Object-oriented programming
   - Class design and modularity
   - External library integration
   - Threading and callbacks

---

## 🎓 Academic Context

This project is suitable for:
- **Bachelor's Degree**: Cybersecurity, Computer Science, Information Technology
- **Course Topics**: Applied Cryptography, Network Security, Secure Programming
- **Learning Outcomes**: Understanding practical encryption implementation
- **Complexity Level**: Intermediate to Advanced

---

## 📄 License

This is an educational project for academic purposes.

---

## 👨‍💻 Author

**Dr. Mohammed Tafik**  
kmkhol01@gmail.com
Cybersecurity 

---

## 🔮 Future Enhancements

Possible improvements for extended projects:
- Add support for multiple encryption algorithms (RSA, ChaCha20)
- Implement digital signatures for file authenticity
- Add compression before encryption
- Support for encrypting entire directories
- Network-based key distribution
- Two-factor authentication for key access
- Cloud storage integration
- Mobile application version

---

## 📞 Support

For questions or issues:
1. Review the troubleshooting section
2. Check the logs for detailed error messages
3. Verify all prerequisites are installed correctly

---

**Remember**: Keep your passwords and keys secure. Lost passwords cannot be recovered, and encrypted files cannot be decrypted without the correct credentials!
