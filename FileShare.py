import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import hashlib
import secrets
import base64
import zlib
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import json
import threading
import logging
from typing import Optional, List, Tuple
try:
    import pyperclip  # pip install pyperclip for better clipboard support
except ImportError:
    pyperclip = None
try:
    import qrcode  # pip install qrcode[pil] for QR code generation
    from PIL import Image, ImageTk
except ImportError:
    qrcode = None
    Image = None
    ImageTk = None
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PasswordStrengthChecker:
    """Enhanced password strength validation"""
    
    @staticmethod
    def check_strength(password: str) -> Tuple[int, str]:
        """Returns strength score (0-4) and description"""
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters")
            
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Include lowercase letters")
            
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Include uppercase letters")
            
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Include numbers")
            
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Include special characters")
            
        strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
        description = strength_levels[min(score, 4)]
        
        if feedback:
            description += f" - {'; '.join(feedback)}"
            
        return min(score, 4), description

class SecureFileSharing:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Secure File Sharing Tool v2.0")
        self.root.geometry("900x700")
        self.root.configure(bg='#1a1a1a')
        
        # Enhanced security settings
        self.kdf_iterations = 300000  # Increased iterations
        self.use_scrypt = True  # More secure KDF
        self.compression_enabled = True
        self.secure_delete = True
        
        # Style configuration
        self.setup_styles()
        
        # Variables - Initialize all key management variables
        self.current_key = None
        self.encrypted_files = []
        self.files_to_encrypt = []
        self.files_to_decrypt = []
        self.password_strength_checker = PasswordStrengthChecker()
        
        # Create main interface
        self.create_widgets()
        
        # Initialize file tracking
        self.refresh_file_list()
        
    def setup_styles(self):
        """Configure modern dark theme styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Dark theme colors
        bg_color = '#1a1a1a'
        fg_color = '#ffffff'
        accent_color = '#0078d4'
        success_color = '#107c10'
        warning_color = '#ff8c00'
        danger_color = '#d13438'
        
        # Configure styles
        style.configure('Title.TLabel',
                       background=bg_color,
                       foreground=fg_color,
                       font=('Segoe UI', 18, 'bold'))
        
        style.configure('Subtitle.TLabel',
                       background=bg_color,
                       foreground='#cccccc',
                       font=('Segoe UI', 10))
        
        style.configure('Modern.TButton',
                       background=accent_color,
                       foreground='white',
                       font=('Segoe UI', 10),
                       padding=(15, 8))
        
        style.map('Modern.TButton',
                 background=[('active', '#106ebe')])
        
        # Progress bar style
        style.configure('Modern.Horizontal.TProgressbar',
                       background=accent_color,
                       troughcolor='#333333',
                       borderwidth=0,
                       lightcolor=accent_color,
                       darkcolor=accent_color)
        
    def create_widgets(self):
        """Create the main GUI widgets with enhanced features"""
        # Main container
        main_frame = tk.Frame(self.root, bg='#1a1a1a')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Enhanced title section
        title_frame = tk.Frame(main_frame, bg='#1a1a1a')
        title_frame.pack(fill='x', pady=(0, 20))
        
        title_label = ttk.Label(title_frame, text="🛡️ Enhanced Secure File Sharing", style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, 
                                 text="AES-256-GCM | Scrypt KDF | Compression | Secure Deletion | Password Strength Analysis", 
                                 style='Subtitle.TLabel')
        subtitle_label.pack(pady=(5, 0))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Enhanced tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_key_management_tab()
        self.create_file_manager_tab()
        self.create_settings_tab()
        
        # Enhanced status bar with progress
        self.create_status_bar(main_frame)
        
    def create_encrypt_tab(self):
        """Enhanced encryption tab with password strength and progress"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="🔒 Encrypt Files")
        
        # File selection section
        file_section = tk.LabelFrame(encrypt_frame, text="Select Files to Encrypt", 
                                   bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 10, 'bold'))
        file_section.pack(fill='x', padx=10, pady=10)
        
        file_button_frame = tk.Frame(file_section, bg='#2d2d2d')
        file_button_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(file_button_frame, text="📂 Select Files", 
                 command=self.select_files_to_encrypt,
                 bg='#0078d4', fg='white', font=('Segoe UI', 10),
                 relief='flat', padx=20, pady=8).pack(side='left')
        
        tk.Button(file_button_frame, text="📁 Select Folder", 
                 command=self.select_folder_to_encrypt,
                 bg='#0078d4', fg='white', font=('Segoe UI', 10),
                 relief='flat', padx=20, pady=8).pack(side='left', padx=(10, 0))
        
        tk.Button(file_button_frame, text="🗑️ Clear List", 
                 command=self.clear_encrypt_list,
                 bg='#d13438', fg='white', font=('Segoe UI', 10),
                 relief='flat', padx=20, pady=8).pack(side='right')
        
        self.selected_files_list = tk.Listbox(file_section, height=5, 
                                            bg='#1a1a1a', fg='#ffffff',
                                            selectbackground='#0078d4',
                                            font=('Consolas', 9))
        scrollbar_files = tk.Scrollbar(file_section, orient='vertical')
        self.selected_files_list.config(yscrollcommand=scrollbar_files.set)
        scrollbar_files.config(command=self.selected_files_list.yview)
        
        self.selected_files_list.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=(0, 10))
        scrollbar_files.pack(side='right', fill='y', pady=(0, 10))
        
        # Enhanced encryption options
        options_section = tk.LabelFrame(encrypt_frame, text="Encryption Options", 
                                      bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 10, 'bold'))
        options_section.pack(fill='x', padx=10, pady=10)
        
        # Password with strength indicator
        pass_frame = tk.Frame(options_section, bg='#2d2d2d')
        pass_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(pass_frame, text="Password:", bg='#2d2d2d', fg='#ffffff', 
                font=('Segoe UI', 10)).pack(anchor='w')
        
        password_entry_frame = tk.Frame(pass_frame, bg='#2d2d2d')
        password_entry_frame.pack(fill='x', pady=(5, 0))
        
        self.encrypt_password = tk.Entry(password_entry_frame, show='*', font=('Segoe UI', 10),
                                       bg='#1a1a1a', fg='#ffffff', insertbackground='#ffffff')
        self.encrypt_password.pack(side='left', fill='x', expand=True)
        self.encrypt_password.bind('<KeyRelease>', self.check_password_strength)
        
        self.show_password_btn = tk.Button(password_entry_frame, text="👁️", 
                                         command=self.toggle_password_visibility,
                                         bg='#333333', fg='white', font=('Segoe UI', 8),
                                         relief='flat', padx=5)
        self.show_password_btn.pack(side='right', padx=(5, 0))
        
        # Password strength indicator
        self.strength_var = tk.StringVar()
        self.strength_label = tk.Label(pass_frame, textvariable=self.strength_var,
                                     bg='#2d2d2d', fg='#cccccc', font=('Segoe UI', 9))
        self.strength_label.pack(anchor='w', pady=(5, 0))
        
        # Encryption settings
        settings_frame = tk.Frame(options_section, bg='#2d2d2d')
        settings_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.compress_var = tk.BooleanVar(value=True)
        tk.Checkbutton(settings_frame, text="Enable compression (reduces file size)",
                      variable=self.compress_var, bg='#2d2d2d', fg='#ffffff',
                      selectcolor='#1a1a1a', font=('Segoe UI', 9)).pack(anchor='w')
        
        self.secure_delete_var = tk.BooleanVar(value=True)
        tk.Checkbutton(settings_frame, text="Secure delete original files",
                      variable=self.secure_delete_var, bg='#2d2d2d', fg='#ffffff',
                      selectcolor='#1a1a1a', font=('Segoe UI', 9)).pack(anchor='w')
        
        # Progress bar
        self.encrypt_progress = ttk.Progressbar(options_section, style='Modern.Horizontal.TProgressbar')
        self.encrypt_progress.pack(fill='x', padx=10, pady=(10, 0))
        
        # Encrypt button
        tk.Button(options_section, text="🔐 Encrypt Files", 
                 command=self.encrypt_files,
                 bg='#107c10', fg='white', font=('Segoe UI', 11, 'bold'),
                 relief='flat', padx=30, pady=10).pack(pady=10)
        
    def create_decrypt_tab(self):
        """Enhanced decryption tab"""
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="🔓 Decrypt Files")
        
        # File selection section
        file_section = tk.LabelFrame(decrypt_frame, text="Select Encrypted Files", 
                                   bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 10, 'bold'))
        file_section.pack(fill='x', padx=10, pady=10)
        
        file_button_frame = tk.Frame(file_section, bg='#2d2d2d')
        file_button_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(file_button_frame, text="📂 Select Encrypted Files", 
                 command=self.select_files_to_decrypt,
                 bg='#0078d4', fg='white', font=('Segoe UI', 10),
                 relief='flat', padx=20, pady=8).pack(side='left')
        
        tk.Button(file_button_frame, text="🗑️ Clear List", 
                 command=self.clear_decrypt_list,
                 bg='#d13438', fg='white', font=('Segoe UI', 10),
                 relief='flat', padx=20, pady=8).pack(side='right')
        
        self.encrypted_files_list = tk.Listbox(file_section, height=5, 
                                             bg='#1a1a1a', fg='#ffffff',
                                             selectbackground='#0078d4',
                                             font=('Consolas', 9))
        scrollbar_enc = tk.Scrollbar(file_section, orient='vertical')
        self.encrypted_files_list.config(yscrollcommand=scrollbar_enc.set)
        scrollbar_enc.config(command=self.encrypted_files_list.yview)
        
        self.encrypted_files_list.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=(0, 10))
        scrollbar_enc.pack(side='right', fill='y', pady=(0, 10))
        
        # Decryption options
        options_section = tk.LabelFrame(decrypt_frame, text="Decryption Options", 
                                      bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 10, 'bold'))
        options_section.pack(fill='x', padx=10, pady=10)
        
        # Password entry
        pass_frame = tk.Frame(options_section, bg='#2d2d2d')
        pass_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(pass_frame, text="Password:", bg='#2d2d2d', fg='#ffffff',
                font=('Segoe UI', 10)).pack(anchor='w')
        
        self.decrypt_password = tk.Entry(pass_frame, show='*', font=('Segoe UI', 10),
                                       bg='#1a1a1a', fg='#ffffff', insertbackground='#ffffff')
        self.decrypt_password.pack(fill='x', pady=(5, 0))
        
        # Output directory selection
        output_frame = tk.Frame(options_section, bg='#2d2d2d')
        output_frame.pack(fill='x', padx=10, pady=(10, 0))
        
        tk.Label(output_frame, text="Output Directory:", bg='#2d2d2d', fg='#ffffff',
                font=('Segoe UI', 10)).pack(anchor='w')
        
        dir_select_frame = tk.Frame(output_frame, bg='#2d2d2d')
        dir_select_frame.pack(fill='x', pady=(5, 0))
        
        self.output_dir_var = tk.StringVar()
        self.output_dir_entry = tk.Entry(dir_select_frame, textvariable=self.output_dir_var,
                                       font=('Segoe UI', 10), bg='#1a1a1a', fg='#ffffff')
        self.output_dir_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(dir_select_frame, text="Browse", 
                 command=self.select_output_directory,
                 bg='#333333', fg='white', font=('Segoe UI', 9),
                 relief='flat', padx=10).pack(side='right', padx=(5, 0))
        
        # Progress bar
        self.decrypt_progress = ttk.Progressbar(options_section, style='Modern.Horizontal.TProgressbar')
        self.decrypt_progress.pack(fill='x', padx=10, pady=(10, 0))
        
        # Decrypt button
        tk.Button(options_section, text="🔓 Decrypt Files", 
                 command=self.decrypt_files,
                 bg='#ff8c00', fg='white', font=('Segoe UI', 11, 'bold'),
                 relief='flat', padx=30, pady=10).pack(pady=10)
        
    def create_key_management_tab(self):
        """Enhanced key management with QR codes"""
        key_frame = ttk.Frame(self.notebook)
        self.notebook.add(key_frame, text="🔑 Key Management")
        
        # Key generation section
        gen_section = tk.LabelFrame(key_frame, text="Generate Secure Key", 
                                  bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 10, 'bold'))
        gen_section.pack(fill='x', padx=10, pady=10)
        
        gen_button_frame = tk.Frame(gen_section, bg='#2d2d2d')
        gen_button_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(gen_button_frame, text="🎲 Generate Random Key", 
                 command=self.generate_key,
                 bg='#9b59b6', fg='white', font=('Segoe UI', 10),
                 relief='flat', padx=20, pady=8).pack(side='left')
        
        # Key length selector
        tk.Label(gen_button_frame, text="Length:", bg='#2d2d2d', fg='#ffffff',
                font=('Segoe UI', 10)).pack(side='left', padx=(20, 5))
        
        self.key_length_var = tk.StringVar(value="32")
        key_length_combo = ttk.Combobox(gen_button_frame, textvariable=self.key_length_var,
                                      values=["16", "32", "64"], state="readonly", width=5)
        key_length_combo.pack(side='left')
        
        # Key display with QR code
        display_frame = tk.Frame(gen_section, bg='#2d2d2d')
        display_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        # Key text display
        key_text_frame = tk.Frame(display_frame, bg='#2d2d2d')
        key_text_frame.pack(side='left', fill='both', expand=True)
        
        tk.Label(key_text_frame, text="Generated Key:", bg='#2d2d2d', fg='#ffffff',
                font=('Segoe UI', 10)).pack(anchor='w')
        
        self.key_display = scrolledtext.ScrolledText(key_text_frame, height=4, 
                                                   bg='#1a1a1a', fg='#ffffff',
                                                   font=('Consolas', 9), wrap='word')
        self.key_display.pack(fill='both', expand=True, pady=(5, 0))
        
        # QR Code display
        qr_frame = tk.Frame(display_frame, bg='#2d2d2d')
        qr_frame.pack(side='right', padx=(10, 0))
        
        tk.Label(qr_frame, text="QR Code:", bg='#2d2d2d', fg='#ffffff',
                font=('Segoe UI', 10)).pack()
        
        self.qr_label = tk.Label(qr_frame, bg='#2d2d2d', width=15, height=8, text="No Key")
        self.qr_label.pack(pady=(5, 0))
        
        # Key operations
        key_ops_frame = tk.Frame(gen_section, bg='#2d2d2d')
        key_ops_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        tk.Button(key_ops_frame, text="💾 Save Key", 
                 command=self.save_key,
                 bg='#107c10', fg='white', font=('Segoe UI', 9),
                 relief='flat', padx=15, pady=5).pack(side='left', padx=(0, 5))
        
        tk.Button(key_ops_frame, text="📋 Copy Key", 
                 command=self.copy_key,
                 bg='#0078d4', fg='white', font=('Segoe UI', 9),
                 relief='flat', padx=15, pady=5).pack(side='left', padx=5)
        
        tk.Button(key_ops_frame, text="📁 Load Key", 
                 command=self.load_key,
                 bg='#ff8c00', fg='white', font=('Segoe UI', 9),
                 relief='flat', padx=15, pady=5).pack(side='left', padx=5)
        
        if qrcode and Image and ImageTk:
            tk.Button(key_ops_frame, text="📱 Export QR", 
                     command=self.export_qr_code,
                     bg='#9b59b6', fg='white', font=('Segoe UI', 9),
                     relief='flat', padx=15, pady=5).pack(side='left', padx=5)
        
    def create_file_manager_tab(self):
        """Enhanced file manager with metadata and batch operations"""
        manager_frame = ttk.Frame(self.notebook)
        self.notebook.add(manager_frame, text="📁 File Manager")
        
        # Control panel
        control_panel = tk.Frame(manager_frame, bg='#2d2d2d')
        control_panel.pack(fill='x', padx=10, pady=10)
        
        tk.Button(control_panel, text="🔄 Refresh", 
                 command=self.refresh_file_list,
                 bg='#0078d4', fg='white', font=('Segoe UI', 9),
                 relief='flat', padx=15, pady=5).pack(side='left', padx=(0, 5))
        
        tk.Button(control_panel, text="🗑️ Delete Selected", 
                 command=self.delete_selected_files,
                 bg='#d13438', fg='white', font=('Segoe UI', 9),
                 relief='flat', padx=15, pady=5).pack(side='left', padx=5)
        
        tk.Button(control_panel, text="📊 File Info", 
                 command=self.show_file_info,
                 bg='#9b59b6', fg='white', font=('Segoe UI', 9),
                 relief='flat', padx=15, pady=5).pack(side='left', padx=5)
        
        # File list section
        list_section = tk.LabelFrame(manager_frame, text="Encrypted Files", 
                                   bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 10, 'bold'))
        list_section.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Enhanced treeview
        columns = ('File', 'Original Name', 'Size', 'Compressed', 'Date', 'KDF', 'Status')
        self.file_tree = ttk.Treeview(list_section, columns=columns, show='headings', height=12)
        
        # Configure columns
        column_widths = {'File': 150, 'Original Name': 120, 'Size': 80, 
                        'Compressed': 80, 'Date': 120, 'KDF': 80, 'Status': 80}
        
        for col in columns:
            self.file_tree.heading(col, text=col)
            self.file_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_section, orient='vertical', command=self.file_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_section, orient='horizontal', command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.file_tree.grid(row=0, column=0, sticky='nsew', padx=(10, 0), pady=10)
        v_scrollbar.grid(row=0, column=1, sticky='ns', pady=10)
        h_scrollbar.grid(row=1, column=0, sticky='ew', padx=(10, 0))
        
        list_section.grid_rowconfigure(0, weight=1)
        list_section.grid_columnconfigure(0, weight=1)
        
    def create_settings_tab(self):
        """Settings tab for security parameters"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Security settings
        security_section = tk.LabelFrame(settings_frame, text="Security Settings", 
                                       bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 10, 'bold'))
        security_section.pack(fill='x', padx=10, pady=10)
        
        # KDF selection
        kdf_frame = tk.Frame(security_section, bg='#2d2d2d')
        kdf_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(kdf_frame, text="Key Derivation Function:", bg='#2d2d2d', fg='#ffffff',
                font=('Segoe UI', 10)).pack(anchor='w')
        
        self.kdf_var = tk.StringVar(value="Scrypt")
        kdf_combo = ttk.Combobox(kdf_frame, textvariable=self.kdf_var,
                               values=["PBKDF2", "Scrypt"], state="readonly")
        kdf_combo.pack(anchor='w', pady=(5, 0))
        
        # Iterations setting
        iter_frame = tk.Frame(security_section, bg='#2d2d2d')
        iter_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(iter_frame, text="KDF Iterations:", bg='#2d2d2d', fg='#ffffff',
                font=('Segoe UI', 10)).pack(anchor='w')
        
        self.iterations_var = tk.StringVar(value="300000")
        iter_entry = tk.Entry(iter_frame, textvariable=self.iterations_var,
                            font=('Segoe UI', 10), bg='#1a1a1a', fg='#ffffff')
        iter_entry.pack(anchor='w', pady=(5, 0))
        
        # Apply settings button
        tk.Button(security_section, text="✅ Apply Settings", 
                 command=self.apply_security_settings,
                 bg='#107c10', fg='white', font=('Segoe UI', 10),
                 relief='flat', padx=20, pady=8).pack(pady=10)
        
    def create_status_bar(self, parent):
        """Enhanced status bar with progress information"""
        status_frame = tk.Frame(parent, bg='#2d2d2d', relief='sunken', bd=1)
        status_frame.pack(side='bottom', fill='x', pady=(10, 0))
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Enhanced Security Mode")
        
        status_label = tk.Label(status_frame, textvariable=self.status_var,
                              bg='#2d2d2d', fg='#ffffff', font=('Segoe UI', 9))
        status_label.pack(side='left', padx=10, pady=5)
        
        # Security indicator
        self.security_indicator = tk.Label(status_frame, text="🛡️ Secure",
                                         bg='#2d2d2d', fg='#107c10', font=('Segoe UI', 9))
        self.security_indicator.pack(side='right', padx=10, pady=5)
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Enhanced key derivation with configurable KDF"""
        try:
            if self.kdf_var.get() == "Scrypt":
                # More secure Scrypt KDF
                kdf = Scrypt(
                    length=32,
                    salt=salt,
                    n=2**14,  # CPU cost (16384)
                    r=8,      # Memory cost
                    p=1,      # Parallelization
                    backend=default_backend()
                )
            else:
                # PBKDF2 fallback
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=int(self.iterations_var.get()),
                    backend=default_backend()
                )
            
            return kdf.derive(password.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise
    
    def encrypt_file(self, file_path: str, password: str) -> bool:
        """Enhanced file encryption with compression and metadata"""
        try:
            # Generate cryptographic parameters
            salt = secrets.token_bytes(32)  # Increased salt size
            iv = secrets.token_bytes(12)
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Read and optionally compress file data
            with open(file_path, 'rb') as f:
                data = f.read()
            
            original_size = len(data)
            compressed = False
            
            if self.compress_var.get() and original_size > 1024:  # Compress files > 1KB
                compressed_data = zlib.compress(data, level=9)
                if len(compressed_data) < original_size * 0.9:  # Only use if >10% reduction
                    data = compressed_data
                    compressed = True
            
            # Encrypt data using AES-256-GCM
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Create comprehensive metadata
            metadata = {
                'version': '2.0',
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode(),
                'tag': base64.b64encode(encryptor.tag).decode(),
                'original_name': os.path.basename(file_path),
                'original_size': original_size,
                'compressed': compressed,
                'compression_ratio': len(data) / original_size if original_size > 0 else 1.0,
                'kdf': self.kdf_var.get(),
                'kdf_iterations': int(self.iterations_var.get()) if self.kdf_var.get() == "PBKDF2" else None,
                'timestamp': datetime.now().isoformat(),
                'file_hash': hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            }
            
            # Write encrypted file
            encrypted_path = file_path + '.sfs'  # Secure File Sharing extension
            with open(encrypted_path, 'wb') as f:
                # Write magic header
                f.write(b'SFS2')  # Secure File Sharing v2.0
                
                # Write metadata
                metadata_bytes = json.dumps(metadata, indent=None).encode('utf-8')
                f.write(len(metadata_bytes).to_bytes(4, 'big'))
                f.write(metadata_bytes)
                f.write(ciphertext)
            
            # Secure delete original file if requested
            if self.secure_delete_var.get():
                self.secure_delete_file(file_path)
            
            logger.info(f"Successfully encrypted: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Encryption failed for {file_path}: {e}")
            messagebox.showerror("Encryption Error", f"Failed to encrypt {os.path.basename(file_path)}: {str(e)}")
            return False
    
    def decrypt_file(self, encrypted_path: str, password: str, output_dir: str = None) -> bool:
        """Enhanced file decryption with compression support"""
        try:
            with open(encrypted_path, 'rb') as f:
                # Verify magic header
                magic = f.read(4)
                if magic != b'SFS2':
                    raise ValueError("Invalid file format or corrupted file")
                
                # Read metadata
                metadata_length = int.from_bytes(f.read(4), 'big')
                metadata_bytes = f.read(metadata_length)
                metadata = json.loads(metadata_bytes.decode('utf-8'))
                
                # Read ciphertext
                ciphertext = f.read()
            
            # Extract encryption parameters
            salt = base64.b64decode(metadata['salt'])
            iv = base64.b64decode(metadata['iv'])
            tag = base64.b64decode(metadata['tag'])
            
            # Derive key with same KDF as used for encryption
            original_kdf = self.kdf_var.get()
            original_iterations = self.iterations_var.get()
            
            # Temporarily use original KDF settings
            self.kdf_var.set(metadata.get('kdf', 'PBKDF2'))
            if metadata.get('kdf_iterations'):
                self.iterations_var.set(str(metadata['kdf_iterations']))
            
            try:
                key = self.derive_key(password, salt)
            finally:
                # Restore current settings
                self.kdf_var.set(original_kdf)
                self.iterations_var.set(original_iterations)
            
            # Decrypt data
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Decompress if needed
            if metadata.get('compressed', False):
                data = zlib.decompress(data)
            
            # Verify file integrity
            if 'file_hash' in metadata:
                if hashlib.sha256(data).hexdigest() != metadata['file_hash']:
                    logger.warning("File integrity check failed - file may be corrupted")
            
            # Write decrypted file
            if output_dir is None:
                output_dir = os.path.dirname(encrypted_path)
            
            original_name = metadata.get('original_name', 'decrypted_file')
            output_path = os.path.join(output_dir, original_name)
            
            # Handle filename conflicts
            counter = 1
            base_name, ext = os.path.splitext(output_path)
            while os.path.exists(output_path):
                output_path = f"{base_name}_{counter}{ext}"
                counter += 1
            
            with open(output_path, 'wb') as f:
                f.write(data)
            
            logger.info(f"Successfully decrypted: {encrypted_path} -> {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Decryption failed for {encrypted_path}: {e}")
            messagebox.showerror("Decryption Error", f"Failed to decrypt {os.path.basename(encrypted_path)}: {str(e)}")
            return False
    
    def secure_delete_file(self, file_path: str, passes: int = 3):
        """Securely delete a file by overwriting with random data"""
        try:
            if not os.path.exists(file_path):
                return
            
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            os.remove(file_path)
            logger.info(f"Securely deleted: {file_path}")
            
        except Exception as e:
            logger.error(f"Secure deletion failed for {file_path}: {e}")
    
    def check_password_strength(self, event=None):
        """Real-time password strength checking"""
        password = self.encrypt_password.get()
        if not password:
            self.strength_var.set("")
            return
        
        score, description = self.password_strength_checker.check_strength(password)
        
        colors = ["#d13438", "#ff8c00", "#ffeb3b", "#9ccc65", "#4caf50"]
        color = colors[score]
        
        self.strength_var.set(f"Strength: {description}")
        self.strength_label.config(fg=color)
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        current = self.encrypt_password.cget('show')
        if current == '*':
            self.encrypt_password.config(show='')
            self.show_password_btn.config(text='🙈')
        else:
            self.encrypt_password.config(show='*')
            self.show_password_btn.config(text='👁️')
    
    def select_folder_to_encrypt(self):
        """Select entire folder for encryption"""
        folder = filedialog.askdirectory(title="Select folder to encrypt")
        if folder:
            files = []
            for root, dirs, filenames in os.walk(folder):
                for filename in filenames:
                    files.append(os.path.join(root, filename))
            
            self.selected_files_list.delete(0, tk.END)
            for file in files:
                self.selected_files_list.insert(tk.END, os.path.relpath(file, folder))
            
            self.files_to_encrypt = files
            self.status_var.set(f"Selected {len(files)} files from folder: {os.path.basename(folder)}")
    
    def clear_encrypt_list(self):
        """Clear encryption file list"""
        self.selected_files_list.delete(0, tk.END)
        self.files_to_encrypt = []
        self.status_var.set("Encryption list cleared")
    
    def clear_decrypt_list(self):
        """Clear decryption file list"""
        self.encrypted_files_list.delete(0, tk.END)
        self.files_to_decrypt = []
        self.status_var.set("Decryption list cleared")
    
    def select_output_directory(self):
        """Select output directory for decrypted files"""
        directory = filedialog.askdirectory(title="Select output directory")
        if directory:
            self.output_dir_var.set(directory)
    
    def generate_qr_code(self, data: str) -> Optional[Image.Image]:
        """Generate QR code for key sharing"""
        if not qrcode or not Image:
            return None
            
        try:
            qr = qrcode.QRCode(version=1, box_size=3, border=4)
            qr.add_data(data)
            qr.make(fit=True)
            return qr.make_image(fill_color="black", back_color="white")
        except Exception as e:
            logger.error(f"QR code generation failed: {e}")
            return None
    
    def update_qr_display(self):
        """Update QR code display"""
        if self.current_key and qrcode and Image and ImageTk:
            qr_image = self.generate_qr_code(self.current_key)
            if qr_image:
                # Resize for display
                qr_image = qr_image.resize((120, 120), Image.Resampling.LANCZOS)
                qr_photo = ImageTk.PhotoImage(qr_image)
                self.qr_label.config(image=qr_photo, text="")
                self.qr_label.image = qr_photo  # Keep reference
            else:
                self.qr_label.config(image='', text='QR Error')
        else:
            self.qr_label.config(image='', text='No Key' if not self.current_key else 'QR N/A')
    
    def export_qr_code(self):
        """Export QR code to file"""
        if not self.current_key:
            messagebox.showwarning("No Key", "Generate a key first")
            return
            
        if not qrcode or not Image:
            messagebox.showerror("QR Code Error", "QR code libraries not available")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save QR code",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg")]
        )
        
        if file_path:
            qr_image = self.generate_qr_code(self.current_key)
            if qr_image:
                qr_image = qr_image.resize((300, 300), Image.Resampling.LANCZOS)
                qr_image.save(file_path)
                messagebox.showinfo("QR Code Saved", f"QR code saved to {file_path}")
    
    def apply_security_settings(self):
        """Apply security settings"""
        try:
            iterations = int(self.iterations_var.get())
            if iterations < 100000:
                messagebox.showwarning("Security Warning", 
                                     "Iterations should be at least 100,000 for security")
                return
            
            self.kdf_iterations = iterations
            messagebox.showinfo("Settings Applied", "Security settings have been applied")
            self.status_var.set(f"Security updated: {self.kdf_var.get()} KDF")
            
        except ValueError:
            messagebox.showerror("Invalid Input", "Iterations must be a valid number")
    
    def show_file_info(self):
        """Show detailed information about selected encrypted file"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file to view info")
            return
        
        item = self.file_tree.item(selection[0])
        filename = item['values'][0]
        
        try:
            with open(filename, 'rb') as f:
                magic = f.read(4)
                if magic != b'SFS2':
                    messagebox.showerror("Invalid File", "Not a valid encrypted file")
                    return
                
                metadata_length = int.from_bytes(f.read(4), 'big')
                metadata_bytes = f.read(metadata_length)
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            # Create info window
            info_window = tk.Toplevel(self.root)
            info_window.title(f"File Information - {filename}")
            info_window.geometry("500x400")
            info_window.configure(bg='#1a1a1a')
            
            # Info display
            info_text = scrolledtext.ScrolledText(info_window, bg='#1a1a1a', fg='#ffffff',
                                                font=('Consolas', 10))
            info_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            info_content = f"""File Information
{'='*50}
Filename: {filename}
Original Name: {metadata.get('original_name', 'Unknown')}
Version: {metadata.get('version', 'Unknown')}
Encryption: AES-256-GCM
KDF: {metadata.get('kdf', 'Unknown')}
KDF Iterations: {metadata.get('kdf_iterations', 'N/A')}

File Details:
Original Size: {metadata.get('original_size', 0):,} bytes
Compressed: {metadata.get('compressed', False)}
Compression Ratio: {metadata.get('compression_ratio', 1.0):.2%}
Creation Date: {metadata.get('timestamp', 'Unknown')}
File Hash: {metadata.get('file_hash', 'Not available')}

Security Parameters:
Salt Length: {len(base64.b64decode(metadata.get('salt', '')))} bytes
IV Length: {len(base64.b64decode(metadata.get('iv', '')))} bytes
Tag Length: {len(base64.b64decode(metadata.get('tag', '')))} bytes
"""
            info_text.insert('1.0', info_content)
            info_text.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file info: {str(e)}")
    
    def delete_selected_files(self):
        """Delete selected encrypted files"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select files to delete")
            return
        
        files_to_delete = [self.file_tree.item(item)['values'][0] for item in selection]
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Are you sure you want to delete {len(files_to_delete)} file(s)?"):
            deleted_count = 0
            for filename in files_to_delete:
                try:
                    self.secure_delete_file(filename)
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Failed to delete {filename}: {e}")
            
            messagebox.showinfo("Delete Complete", f"Successfully deleted {deleted_count} file(s)")
            self.refresh_file_list()
    
    def select_files_to_encrypt(self):
        """Select files for encryption"""
        files = filedialog.askopenfilenames(
            title="Select files to encrypt",
            filetypes=[("All files", "*.*")]
        )
        
        if files:  # Only update if files were selected
            self.selected_files_list.delete(0, tk.END)
            for file in files:
                self.selected_files_list.insert(tk.END, os.path.basename(file))
                
            self.files_to_encrypt = list(files)  # Convert to list and store
            self.status_var.set(f"Selected {len(files)} files for encryption")
        
    def select_files_to_decrypt(self):
        """Select encrypted files for decryption"""
        files = filedialog.askopenfilenames(
            title="Select encrypted files",
            filetypes=[("Secure File Sharing", "*.sfs"), ("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        
        if files:  # Only update if files were selected
            self.encrypted_files_list.delete(0, tk.END)
            for file in files:
                self.encrypted_files_list.insert(tk.END, os.path.basename(file))
                
            self.files_to_decrypt = list(files)  # Convert to list and store
            self.status_var.set(f"Selected {len(files)} files for decryption")
        
    def encrypt_files(self):
        """Encrypt selected files with progress tracking"""
        if not hasattr(self, 'files_to_encrypt') or not self.files_to_encrypt:
            messagebox.showwarning("No Files", "Please select files to encrypt first")
            return
            
        password = self.encrypt_password.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password")
            return
        
        # Check password strength
        score, _ = self.password_strength_checker.check_strength(password)
        if score < 2:
            if not messagebox.askyesno("Weak Password", 
                                     "Your password is weak. Continue anyway?"):
                return
        
        def encrypt_thread():
            success_count = 0
            total_files = len(self.files_to_encrypt)
            
            self.encrypt_progress['maximum'] = total_files
            self.encrypt_progress['value'] = 0
            
            for i, file_path in enumerate(self.files_to_encrypt):
                self.status_var.set(f"Encrypting {i+1}/{total_files}: {os.path.basename(file_path)}")
                self.root.update()
                
                if self.encrypt_file(file_path, password):
                    success_count += 1
                
                self.encrypt_progress['value'] = i + 1
                self.root.update()
                    
            self.encrypt_progress['value'] = 0
            self.status_var.set(f"Encryption complete: {success_count}/{total_files} files encrypted")
            messagebox.showinfo("Encryption Complete", 
                              f"Successfully encrypted {success_count} out of {total_files} files")
            self.refresh_file_list()
            
        threading.Thread(target=encrypt_thread, daemon=True).start()
        
    def decrypt_files(self):
        """Decrypt selected files with progress tracking"""
        if not hasattr(self, 'files_to_decrypt') or not self.files_to_decrypt:
            messagebox.showwarning("No Files", "Please select encrypted files first")
            return
            
        password = self.decrypt_password.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password")
            return
        
        output_dir = self.output_dir_var.get()
        if not output_dir:
            output_dir = filedialog.askdirectory(title="Select output directory for decrypted files")
            if not output_dir:
                return
            self.output_dir_var.set(output_dir)
            
        def decrypt_thread():
            success_count = 0
            total_files = len(self.files_to_decrypt)
            
            self.decrypt_progress['maximum'] = total_files
            self.decrypt_progress['value'] = 0
            
            for i, file_path in enumerate(self.files_to_decrypt):
                self.status_var.set(f"Decrypting {i+1}/{total_files}: {os.path.basename(file_path)}")
                self.root.update()
                
                if self.decrypt_file(file_path, password, output_dir):
                    success_count += 1
                
                self.decrypt_progress['value'] = i + 1
                self.root.update()
                    
            self.decrypt_progress['value'] = 0
            self.status_var.set(f"Decryption complete: {success_count}/{total_files} files decrypted")
            messagebox.showinfo("Decryption Complete", 
                              f"Successfully decrypted {success_count} out of {total_files} files")
            
        threading.Thread(target=decrypt_thread, daemon=True).start()
        
    def generate_key(self):
        """Generate a random secure key with configurable length - FIXED VERSION"""
        try:
            length = int(self.key_length_var.get())
            # Generate secure random key
            key = secrets.token_urlsafe(length)
            
            # Clear and insert the key into the display
            self.key_display.delete('1.0', tk.END)
            self.key_display.insert('1.0', key)
            
            # Store the key
            self.current_key = key
            
            # Update status
            self.status_var.set(f"Generated {length*8}-bit secure key")
            
            # Update QR code display
            self.update_qr_display()
            
            logger.info(f"Generated key of length {length}")
            
        except ValueError as e:
            logger.error(f"Key generation failed: {e}")
            messagebox.showerror("Invalid Length", "Please select a valid key length")
        except Exception as e:
            logger.error(f"Unexpected error in key generation: {e}")
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")
        
    def save_key(self):
        """Save the current key to file - FIXED VERSION"""
        if not self.current_key:
            messagebox.showwarning("No Key", "Generate or load a key first")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save key file",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.current_key)
                messagebox.showinfo("Key Saved", f"Key successfully saved to:\n{file_path}")
                logger.info(f"Key saved to {file_path}")
            except Exception as e:
                logger.error(f"Failed to save key: {e}")
                messagebox.showerror("Save Error", f"Failed to save key: {str(e)}")
            
    def copy_key(self):
        """Copy key to clipboard - FIXED VERSION"""
        if not self.current_key:
            messagebox.showwarning("No Key", "Generate or load a key first")
            return
        
        try:
            if pyperclip:
                pyperclip.copy(self.current_key)
                messagebox.showinfo("Key Copied", "Key copied to clipboard using pyperclip")
            else:
                # Fallback to tkinter clipboard
                self.root.clipboard_clear()
                self.root.clipboard_append(self.current_key)
                self.root.update()  # Ensure clipboard is updated
                messagebox.showinfo("Key Copied", "Key copied to clipboard")
            
            logger.info("Key copied to clipboard")
            
        except Exception as e:
            logger.error(f"Failed to copy key: {e}")
            messagebox.showerror("Copy Error", f"Failed to copy key: {str(e)}")
        
    def load_key(self):
        """Load key from file - FIXED VERSION"""
        file_path = filedialog.askopenfilename(
            title="Load key file",
            filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    key = f.read().strip()
                    
                if not key:
                    messagebox.showerror("Empty File", "The selected file is empty or contains no valid key")
                    return
                    
                # Clear and insert the key into the display
                self.key_display.delete('1.0', tk.END)
                self.key_display.insert('1.0', key)
                
                # Store the key
                self.current_key = key
                
                # Update QR code display
                self.update_qr_display()
                
                # Update status
                self.status_var.set(f"Key loaded from {os.path.basename(file_path)}")
                
                messagebox.showinfo("Key Loaded", f"Key successfully loaded from:\n{file_path}")
                logger.info(f"Key loaded from {file_path}")
                
            except Exception as e:
                logger.error(f"Failed to load key: {e}")
                messagebox.showerror("Load Error", f"Failed to load key: {str(e)}")
                
    def refresh_file_list(self):
        """Refresh the file manager list with enhanced metadata"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
            
        # Find encrypted files in current directory
        try:
            current_dir = os.getcwd()
            encrypted_files_found = 0
            
            for file in os.listdir(current_dir):
                if file.endswith(('.sfs', '.encrypted')):
                    try:
                        file_path = os.path.join(current_dir, file)
                        size = os.path.getsize(file_path)
                        date = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M')
                        
                        # Try to read metadata
                        original_name = "Unknown"
                        compressed = "No"
                        kdf = "Unknown"
                        
                        try:
                            with open(file_path, 'rb') as f:
                                magic = f.read(4)
                                if magic == b'SFS2':
                                    metadata_length = int.from_bytes(f.read(4), 'big')
                                    metadata_bytes = f.read(metadata_length)
                                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                                    
                                    original_name = metadata.get('original_name', 'Unknown')
                                    compressed = "Yes" if metadata.get('compressed', False) else "No"
                                    kdf = metadata.get('kdf', 'Unknown')
                        except:
                            pass  # Ignore metadata read errors
                        
                        self.file_tree.insert('', 'end', values=(
                            file, original_name, f"{size:,} bytes", 
                            compressed, date, kdf, "Encrypted"
                        ))
                        
                        encrypted_files_found += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing file {file}: {e}")
            
            self.status_var.set(f"Found {encrypted_files_found} encrypted files")
                        
        except Exception as e:
            logger.error(f"Error refreshing file list: {e}")
            self.status_var.set(f"Error refreshing file list: {str(e)}")

def main():
    """Main function to run the enhanced application"""
    root = tk.Tk()
    app = SecureFileSharing(root)
    root.mainloop()

if __name__ == "__main__":
    main()