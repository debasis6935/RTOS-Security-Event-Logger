import random
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
from file_access import FileAccessGUI  # Import the new file access GUI

class AuthSystem:
    def __init__(self):
        self.users = {}  # Store username: password pairs (insecure for demo purposes)
        self.logged_in_user = None
        self.otp = None
        self.otp_expiry = None
        self.pending_username = None
        self.pending_password = None

    def register(self, username, password):
        if username in self.users:
            return "Username already exists!"
        self.users[username] = password
        return f"User {username} registered successfully!"

    def generate_otp(self, username, password):
        if username not in self.users:
            return "Username not registered!"
        if self.users[username] != password:
            return "Incorrect password!"
        self.pending_username = username
        self.pending_password = password
        self.otp = str(random.randint(100000, 999999))
        self.otp_expiry = time.time() + 60  # OTP valid for 60 seconds
        return f"OTP generated: {self.otp} (valid for 60 seconds)"

    def login(self, input_otp):
        if not self.pending_username or not self.otp:
            return "Please generate OTP first!"
        if time.time() > self.otp_expiry:
            self.otp = None
            self.pending_username = None
            self.pending_password = None
            return "OTP expired! Please generate a new OTP."
        if input_otp == self.otp:
            self.logged_in_user = self.pending_username
            self.otp = None
            self.otp_expiry = None
            self.pending_username = None
            self.pending_password = None
            return f"Login successful! Welcome, {self.logged_in_user}."
        return "Invalid OTP!"

class AuthSystemGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Login System")
        self.root.geometry("800x600")
        self.auth = AuthSystem()

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Dark.TLabel", background="#16213e", foreground="white", font=("Helvetica", 10))
        style.configure("Header.TLabel", background="#16213e", foreground="#00d4ff", font=("Helvetica", 16, "bold"))

        # Main canvas with gradient
        self.canvas = tk.Canvas(root, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Configure>", self.update_gradient)

        # Main frame
        main_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=main_frame, anchor="nw")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header
        header = ttk.Label(main_frame, text="Secure Login System", style="Header.TLabel")
        header.pack(pady=(10, 20))

        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Register Tab
        register_frame = ttk.Frame(notebook)
        notebook.add(register_frame, text="Register")
        self.setup_register_tab(register_frame)

        # Login Tab
        login_frame = ttk.Frame(notebook)
        notebook.add(login_frame, text="Login")
        self.setup_login_tab(login_frame)

    def update_gradient(self, event):
        width = event.width
        height = event.height
        self.canvas.delete("gradient")
        self.canvas.create_rectangle(0, 0, width, height, fill="#1a1a2e", outline="#1a1a2e", tags="gradient")
        self.canvas.create_rectangle(0, 0, width, height // 2, fill="#16213e", outline="#16213e", tags="gradient")

    def setup_register_tab(self, frame):
        input_frame = ttk.Frame(frame)
        input_frame.pack(pady=20)

        ttk.Label(input_frame, text="Username:", style="Dark.TLabel").grid(row=0, column=0, padx=5, pady=5)
        self.reg_username_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.reg_username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="Password:", style="Dark.TLabel").grid(row=1, column=0, padx=5, pady=5)
        self.reg_password_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.reg_password_var, show="*").grid(row=1, column=1, padx=5, pady=5)

        button_style = {"font": ("Helvetica", 11, "bold"), "relief": "flat", "bd": 0, "width": 15, "pady": 5}
        reg_btn = tk.Button(input_frame, text="Register", command=self.register, bg="#00d4ff", fg="white", **button_style)
        reg_btn.grid(row=2, column=1, pady=10)

        self.reg_display = scrolledtext.ScrolledText(frame, height=15, bg="#1e1e1e", fg="#ffffff", font=("Consolas", 10))
        self.reg_display.pack(fill=tk.BOTH, expand=True, pady=10)

    def setup_login_tab(self, frame):
        input_frame = ttk.Frame(frame)
        input_frame.pack(pady=20)

        ttk.Label(input_frame, text="Username:", style="Dark.TLabel").grid(row=0, column=0, padx=5, pady=5)
        self.login_username_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.login_username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="Password:", style="Dark.TLabel").grid(row=1, column=0, padx=5, pady=5)
        self.login_password_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.login_password_var, show="*").grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="OTP:", style="Dark.TLabel").grid(row=2, column=0, padx=5, pady=5)
        self.otp_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.otp_var).grid(row=2, column=1, padx=5, pady=5)

        button_style = {"font": ("Helvetica", 11, "bold"), "relief": "flat", "bd": 0, "width": 15, "pady": 5}
        otp_btn = tk.Button(input_frame, text="Generate OTP", command=self.generate_otp, bg="#f8a51d", fg="white", **button_style)
        otp_btn.grid(row=3, column=1, pady=5)

        login_btn = tk.Button(input_frame, text="Login", command=self.login, bg="#2ecc71", fg="white", **button_style)
        login_btn.grid(row=4, column=1, pady=5)

        self.login_display = scrolledtext.ScrolledText(frame, height=15, bg="#1e1e1e", fg="#ffffff", font=("Consolas", 10))
        self.login_display.pack(fill=tk.BOTH, expand=True, pady=10)

    def register(self):
        username = self.reg_username_var.get()
        password = self.reg_password_var.get()
        result = self.auth.register(username, password)
        self.reg_display.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {result}\n")
        self.reg_display.see(tk.END)

    def generate_otp(self):
        username = self.login_username_var.get()
        password = self.login_password_var.get()
        result = self.auth.generate_otp(username, password)
        self.login_display.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {result}\n")
        self.login_display.see(tk.END)

    def login(self):
        otp = self.otp_var.get()
        result = self.auth.login(otp)
        self.login_display.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {result}\n")
        self.login_display.see(tk.END)
        if "Login successful" in result:
            self.open_file_access_window()

    def open_file_access_window(self):
        file_window = tk.Toplevel(self.root)
        FileAccessGUI(file_window, self.auth, self.root)  # Pass the root to reopen later
        self.root.withdraw()  # Hide the login window

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthSystemGUI(root)
    root.mainloop()