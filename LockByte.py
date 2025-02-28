import os
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import re
import secrets
import string

class SecureEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Vault")
        self.root.geometry("750x500")
        

        self.iterations = 600_000 
        self.min_password_length = 12
        self.secure_delete_passes = 3
        
        self.create_widgets()
        self.setup_layout()
        self.setup_security_checks()

    def create_widgets(self):

        self.file_frame = ttk.LabelFrame(self.root, text="File Operations")
        self.file_path = tk.StringVar()
        self.file_label = ttk.Label(self.file_frame, text="No file selected")
        self.browse_btn = ttk.Button(self.file_frame, text="Browse", command=self.select_file)
        

        self.pwd_frame = ttk.LabelFrame(self.root, text="Password Security")
        self.password = tk.StringVar()
        self.password.trace_add("write", self.update_password_strength)
        self.pwd_entry = ttk.Entry(self.pwd_frame, show="•", textvariable=self.password)
        self.show_pwd = tk.BooleanVar()
        self.show_pwd_cb = ttk.Checkbutton(self.pwd_frame, text="Show", 
                                         variable=self.show_pwd,
                                         command=self.toggle_password)
        self.strength_label = ttk.Label(self.pwd_frame, text="Password Strength: ")
        self.generate_btn = ttk.Button(self.pwd_frame, text="Generate", command=self.generate_password)
        

        self.opt_frame = ttk.LabelFrame(self.root, text="Security Options")
        self.secure_delete = tk.BooleanVar(value=True)
        self.delete_cb = ttk.Checkbutton(self.opt_frame, text="Secure Delete Original", 
                                       variable=self.secure_delete)
        self.passes_var = tk.IntVar(value=3)
        self.passes_spin = ttk.Spinbox(self.opt_frame, from_=1, to=7, 
                                     textvariable=self.passes_var, width=3)
        

        self.btn_frame = ttk.Frame(self.root)
        self.encrypt_btn = ttk.Button(self.btn_frame, text="Encrypt", command=self.encrypt_file)
        self.decrypt_btn = ttk.Button(self.btn_frame, text="Decrypt", command=self.decrypt_file)
        

        self.status_area = scrolledtext.ScrolledText(self.root, state='disabled', height=10)
        self.security_warning = ttk.Label(self.root, 
                                        text="Warning: Always verify backups and store passwords securely!",
                                        foreground="red")

    def setup_layout(self):
        self.file_frame.pack(pady=5, padx=5, fill="x")
        self.file_label.pack(side="left", padx=5, expand=True, fill="x")
        self.browse_btn.pack(side="right", padx=5)
        
        self.pwd_frame.pack(pady=5, padx=5, fill="x")
        self.pwd_entry.pack(side="left", padx=5, expand=True, fill="x")
        self.show_pwd_cb.pack(side="left", padx=5)
        self.generate_btn.pack(side="left", padx=5)
        self.strength_label.pack(side="left", padx=5)
        
        self.opt_frame.pack(pady=5, padx=5, fill="x")
        self.delete_cb.pack(side="left", padx=5)
        ttk.Label(self.opt_frame, text="Shred Passes:").pack(side="left", padx=5)
        self.passes_spin.pack(side="left", padx=5)
        
        self.btn_frame.pack(pady=10)
        self.encrypt_btn.pack(side="left", padx=20)
        self.decrypt_btn.pack(side="left", padx=20)
        
        self.status_area.pack(pady=5, padx=5, fill="both", expand=True)
        self.security_warning.pack(pady=5, anchor="center")

    def setup_security_checks(self):
        self.complexity_reqs = {
            'length': self.min_password_length,
            'upper': True,
            'lower': True,
            'digit': True,
            'special': True
        }

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)
            self.file_label.config(text=file_path)
            self.log_message(f"Selected file: {file_path}")

    def toggle_password(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "•")

    def log_message(self, message, error=False):
        self.status_area.config(state='normal')
        tag = "error" if error else "info"
        self.status_area.insert("end", message + "\n", tag)
        self.status_area.see("end")
        self.status_area.config(state='disabled')
        self.root.update()

    def update_password_strength(self, *args):
        pwd = self.password.get()
        score = 0
        

        length = len(pwd)
        if length >= self.min_password_length:
            score += 2
        elif length >= 8:
            score += 1
            

        has_upper = re.search(r'[A-Z]', pwd)
        has_lower = re.search(r'[a-z]', pwd)
        has_digit = re.search(r'\d', pwd)
        has_special = re.search(r'[^A-Za-z0-9]', pwd)
        
        score += sum([1 for req in [has_upper, has_lower, has_digit, has_special] if req])
        

        colors = {0: "red", 1: "orange", 2: "yellow", 3: "green"}
        strength = min(score // 2, 3)
        self.strength_label.config(
            text=f"Password Strength: {'★' * strength}{'☆' * (3 - strength)}",
            foreground=colors.get(strength, "red")
        )

    def generate_password(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            pwd = ''.join(secrets.choice(chars) for _ in range(16))
            if (re.search(r'[A-Z]', pwd) and
                re.search(r'[a-z]', pwd) and
                re.search(r'\d', pwd) and
                re.search(r'[^A-Za-z0-9]', pwd)):
                self.password.set(pwd)
                break

    def secure_delete_file(self, file_path):
        try:
            with open(file_path, "ba+") as f:
                length = f.tell()
                for _ in range(self.passes_var.get()):
                    f.seek(0)
                    f.write(os.urandom(length))
                f.truncate()
            os.remove(file_path)
            return True
        except Exception as e:
            self.log_message(f"Secure delete failed: {str(e)}", error=True)
            return False

    def validate_password(self):
        pwd = self.password.get()
        if len(pwd) < self.min_password_length:
            messagebox.showwarning("Weak Password", 
                f"Password must be at least {self.min_password_length} characters!")
            return False
        if not all([
            re.search(r'[A-Z]', pwd),
            re.search(r'[a-z]', pwd),
            re.search(r'\d', pwd),
            re.search(r'[^A-Za-z0-9]', pwd)
        ]):
            messagebox.showwarning("Weak Password",
                "Password must contain:\n- Uppercase letters\n- Lowercase letters\n"
                "- Numbers\n- Special characters")
            return False
        return True

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self):
        if not self.validate_password():
            return
            
        try:
            file_path = self.file_path.get()
            if not file_path:
                raise ValueError("Please select a file to encrypt")
                
            with open(file_path, "rb") as f:
                data = f.read()
            
            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = self.derive_key(self.password.get(), salt)
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            encrypted_data = salt + nonce + encryptor.tag + ciphertext
            output_path = file_path + ".enc"
            
            with open(output_path, "wb") as f:
                f.write(encrypted_data)
            
            if self.secure_delete.get():
                if self.secure_delete_file(file_path):
                    self.log_message(f"Original file securely deleted")
            
            self.log_message(f"Encryption successful!\nSaved to: {output_path}")
            
        except Exception as e:
            self.log_message(f"Encryption error: {str(e)}", error=True)

    def decrypt_file(self):
        if not self.validate_password():
            return
            
        try:
            file_path = self.file_path.get()
            if not file_path.endswith(".enc"):
                raise ValueError("Please select a .enc file for decryption")
                
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
            
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            ciphertext = encrypted_data[44:]
            
            key = self.derive_key(self.password.get(), salt)
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            output_path = file_path[:-4] if file_path.endswith(".enc") else file_path + ".dec"
            
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
            
            if self.secure_delete.get():
                if self.secure_delete_file(file_path):
                    self.log_message(f"Encrypted file securely deleted")
            
            self.log_message(f"Decryption successful!\nSaved to: {output_path}")
            
        except Exception as e:
            self.log_message(f"Decryption error: {str(e)}", error=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureEncryptionApp(root)
    app.status_area.tag_config("info", foreground="blue")
    app.status_area.tag_config("error", foreground="red")
    root.mainloop()
