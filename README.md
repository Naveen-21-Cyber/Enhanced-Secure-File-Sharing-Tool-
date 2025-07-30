# 🛡️ Enhanced Secure File Sharing Tool 

A modern, feature-rich file encryption application built with Python and Tkinter, providing military-grade security for your sensitive files.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/encryption-AES--256--GCM-red.svg)
![KDF](https://img.shields.io/badge/KDF-Scrypt%20%7C%20PBKDF2-orange.svg)

## Screenshot 📸

<img width="1920" height="1080" alt="fs1" src="https://github.com/user-attachments/assets/b94b0fd5-ab2f-45c7-b134-4df46abf933e" />
<br>
<img width="1920" height="1080" alt="fs2" src="https://github.com/user-attachments/assets/1678294d-32c2-42e0-8b7a-29b2f464c5e6" />
<br>
<img width="407" height="288" alt="fs4" src="https://github.com/user-attachments/assets/b8ce5ace-f96b-4831-af7f-41fc68f1c9af" />
<br>
<img width="180" height="200" alt="fs5" src="https://github.com/user-attachments/assets/45fe1d63-0377-43ab-982b-1d8083560092" />
<br>
<img width="1920" height="1080" alt="fs3" src="https://github.com/user-attachments/assets/90ea88dd-3f48-4101-b162-87d26424ad7e" />


## ✨ Features

### 🔐 Advanced Security
- **AES-256-GCM Encryption** - Industry-standard authenticated encryption
- **Scrypt & PBKDF2 Key Derivation** - Configurable KDF with high iteration counts
- **Cryptographically Secure Random Generation** - Using Python's `secrets` module
- **File Integrity Verification** - SHA-256 checksums for tamper detection
- **Secure Memory Handling** - Proper key derivation and cleanup

### 🎨 Modern Interface
- **Dark Theme UI** - Professional, eye-friendly interface
- **Tabbed Navigation** - Organized workflow for different operations
- **Real-time Progress Tracking** - Visual feedback during operations
- **Password Strength Indicator** - Live password security assessment
- **Enhanced File Manager** - Detailed metadata viewing and batch operations

### 🚀 Advanced Features
- **Compression Support** - Automatic file compression before encryption
- **Batch Processing** - Encrypt/decrypt multiple files simultaneously
- **Secure File Deletion** - Multi-pass overwriting of original files
- **QR Code Generation** - Easy key sharing via QR codes
- **Folder Encryption** - Recursive encryption of entire directories
- **Metadata Preservation** - Original filename and timestamp tracking

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- Windows, macOS, or Linux
- Minimum 100MB free disk space

### Required Libraries
```bash
# Core cryptography
cryptography>=3.4.8

# GUI framework (usually included with Python)
tkinter

# Optional libraries for enhanced features
pyperclip>=1.8.2    # Enhanced clipboard support
qrcode[pil]>=7.3.1  # QR code generation
Pillow>=8.3.2       # Image processing for QR codes
```

## 🚀 Installation

### Option 1: Clone Repository
```bash
git clone https://github.com/yourusername/secure-file-sharing.git
cd secure-file-sharing
pip install -r requirements.txt
python FileShare.py
```

### Option 2: Direct Download
1. Download the `FileShare.py` file
2. Install required dependencies:
```bash
pip install cryptography pyperclip qrcode[pil]
```
3. Run the application:
```bash
python FileShare.py
```

### requirements.txt
```txt
cryptography>=3.4.8
pyperclip>=1.8.2
qrcode[pil]>=7.3.1
Pillow>=8.3.2
```

## 🎯 Quick Start Guide

### 1. First Launch
- Run `python FileShare.py`
- The application opens with a modern dark theme interface
- Navigate through tabs: Encrypt, Decrypt, Key Management, File Manager, Settings

### 2. Encrypting Files
1. Go to the **🔒 Encrypt Files** tab
2. Click **📂 Select Files** or **📁 Select Folder**
3. Enter a strong password (strength indicator will guide you)
4. Configure options:
   - ✅ Enable compression (recommended)
   - ✅ Secure delete original files (optional)
5. Click **🔐 Encrypt Files**

### 3. Decrypting Files
1. Go to the **🔓 Decrypt Files** tab
2. Click **📂 Select Encrypted Files** (look for `.sfs` files)
3. Enter the password used for encryption
4. Select output directory
5. Click **🔓 Decrypt Files**

### 4. Key Management
1. Go to the **🔑 Key Management** tab
2. Generate secure random keys for sharing
3. Save keys to files or copy to clipboard
4. Generate QR codes for easy mobile sharing

## 🔧 Configuration Options

### Security Settings
- **Key Derivation Function**: Choose between Scrypt (recommended) or PBKDF2
- **KDF Iterations**: Default 300,000 (minimum 100,000 recommended)
- **Compression**: Automatic compression for files > 1KB
- **Secure Deletion**: 3-pass overwriting of original files

### File Format
Encrypted files use the `.sfs` (Secure File Sharing) extension with this structure:
```
[4 bytes] Magic header: "SFS2"
[4 bytes] Metadata length
[Variable] JSON metadata (original name, timestamps, security params)
[Variable] Encrypted file data
```

## 🛡️ Security Features

### Encryption Specifications
- **Algorithm**: AES-256 in GCM mode
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes) - cryptographically random
- **Salt Size**: 256 bits (32 bytes) - unique per file
- **Authentication Tag**: 128 bits (16 bytes)

### Key Derivation
#### Scrypt (Default - Recommended)
- **CPU Cost (N)**: 16,384 (2^14)
- **Memory Cost (r)**: 8
- **Parallelization (p)**: 1
- **Output Length**: 32 bytes

#### PBKDF2 (Alternative)
- **Hash Function**: SHA-256
- **Iterations**: 300,000 (configurable)
- **Salt**: 32 bytes random
- **Output Length**: 32 bytes

### Password Security
Real-time strength assessment based on:
- Length (minimum 8 characters recommended)
- Character diversity (uppercase, lowercase, digits, symbols)
- Common password patterns detection

## 📊 File Manager Features

The built-in file manager provides:
- **Metadata Viewing**: Original filenames, compression ratios, encryption parameters
- **Batch Operations**: Select and delete multiple encrypted files
- **File Integrity**: Built-in checksum verification
- **Size Analysis**: Before/after encryption size comparison

## 🔍 Troubleshooting

### Common Issues

#### "Module not found" errors
```bash
pip install --upgrade cryptography pyperclip qrcode[pil]
```

#### QR Code features not working
```bash
pip install qrcode[pil] Pillow
```

#### Decryption fails
- Verify password is correct
- Check file is not corrupted
- Ensure file has `.sfs` extension and proper format

#### Performance issues
- Reduce KDF iterations in Settings (minimum 100,000)
- Disable compression for already compressed files
- Close other applications during large file operations

### Error Logs
The application logs important events to help with debugging:
- Encryption/decryption operations
- Key generation and management
- Security parameter changes
- File operations and errors

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup
```bash
git clone https://github.com/yourusername/secure-file-sharing.git
cd secure-file-sharing
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python FileShare.py
```

### Code Style
- Follow PEP 8 style guidelines
- Add docstrings to all functions and classes
- Include type hints where appropriate
- Write unit tests for new features

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🔐 Security Disclaimer

This tool is designed for legitimate file protection purposes. Users are responsible for:
- Using strong, unique passwords
- Keeping passwords secure and backed up
- Understanding that forgotten passwords cannot be recovered
- Complying with local laws and regulations regarding encryption

**⚠️ Important**: Always test decryption on a copy before deleting original files.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/secure-file-sharing/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/secure-file-sharing/discussions)
- **Security**: Report security issues privately via email

## 🏆 Acknowledgments

- [Cryptography Library](https://cryptography.io/) - For robust cryptographic primitives
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - For GUI framework
- [Python Security Team](https://www.python.org/dev/security/) - For security best practices

---

<div align="center">

**⭐ Star this repository if you find it useful!**

Made with ❤️ for secure file sharing

</div>
