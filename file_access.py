import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog

class FileAccessGUI:
    def __init__(self, root, auth_system, login_root):
        self.root = root
        self.root.title("File Access System")
        self.root.geometry("800x600")
        self.auth = auth_system
        self.login_root = login_root
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.write_file_path = "secure_log.txt"  # Default write file

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Dark.TLabel", background="#16213e", foreground="white", font=("Helvetica", 10))
        style.configure("Header.TLabel", background="#16213e", foreground="#00d4ff", font=("Helvetica", 16, "bold"))

        self.canvas = tk.Canvas(root, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Configure>", self.update_gradient)

        main_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=main_frame, anchor="nw")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        header = ttk.Label(main_frame, text=f"File Access - {self.auth.logged_in_user}", style="Header.TLabel")
        header.pack(pady=(10, 20))

        ttk.Label(main_frame, text="Content to Write:", style="Dark.TLabel").pack(pady=5)
        self.content_var = tk.StringVar()
        content_entry = ttk.Entry(main_frame, textvariable=self.content_var, width=50)
        content_entry.pack(pady=5)

        ttk.Label(main_frame, text="File Path to Read:", style="Dark.TLabel").pack(pady=5)
        self.read_file_path_var = tk.StringVar()
        read_path_entry = ttk.Entry(main_frame, textvariable=self.read_file_path_var, width=50)
        read_path_entry.pack(pady=5)
        browse_btn = tk.Button(main_frame, text="Browse", command=self.browse_file, bg="#f8a51d", fg="white", 
                               font=("Helvetica", 11, "bold"), relief="flat", bd=0, width=15, pady=5)
        browse_btn.pack(pady=5)

        button_style = {"font": ("Helvetica", 11, "bold"), "relief": "flat", "bd": 0, "width": 15, "pady": 5}
        write_btn = tk.Button(main_frame, text="Write to File", command=self.write_to_file, bg="#3498db", fg="white", **button_style)
        write_btn.pack(pady=5)

        read_btn = tk.Button(main_frame, text="Read from File", command=self.read_from_file, bg="#9b59b6", fg="white", **button_style)
        read_btn.pack(pady=5)

        logout_btn = tk.Button(main_frame, text="Logout", command=self.logout, bg="#e94560", fg="white", **button_style)
        logout_btn.pack(pady=5)

        self.display = scrolledtext.ScrolledText(main_frame, height=15, bg="#1e1e1e", fg="#ffffff", font=("Consolas", 10))
        self.display.pack(fill=tk.BOTH, expand=True, pady=10)

    def update_gradient(self, event):
        width = event.width
        height = event.height
        self.canvas.delete("gradient")
        self.canvas.create_rectangle(0, 0, width, height, fill="#1a1a2e", outline="#1a1a2e", tags="gradient")
        self.canvas.create_rectangle(0, 0, width, height // 2, fill="#16213e", outline="#16213e", tags="gradient")

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Read", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            self.read_file_path_var.set(file_path)

    def write_to_file(self):
        content = self.content_var.get()
        if self.auth.logged_in_user is None:
            result = "Access denied! Please log in first."
        else:
            try:
                with open(self.write_file_path, 'a') as f:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"[{timestamp}] {self.auth.logged_in_user}: {content}\n")
                result = "Content written successfully!"
            except Exception as e:
                result = f"Error writing to file: {str(e)}"
        self.display.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {result}\n")
        self.display.see(tk.END)

    def read_from_file(self):
        file_path = self.read_file_path_var.get()
        if self.auth.logged_in_user is None:
            result = "Access denied! Please log in first."
        elif not file_path:
            result = "Please specify a file path!"
        elif not os.path.exists(file_path):
            result = "File does not exist!"
        else:
            try:
                with open(file_path, 'r') as f:
                    result = f.read()
            except Exception as e:
                result = f"Error reading file: {str(e)}"
        self.display.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {result}\n")
        self.display.see(tk.END)

    def logout(self):
        if self.auth.logged_in_user:
            self.auth.logged_in_user = None
            self.auth.otp = None
            self.auth.otp_expiry = None
            self.auth.pending_username = None
            self.auth.pending_password = None
            result = "Logged out successfully!"
        else:
            result = "No user is currently logged in!"
        self.display.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {result}\n")
        self.display.see(tk.END)
        self.root.destroy()  # Close file access window
        self.login_root.deiconify()  # Return to login page

    def on_closing(self):
        self.logout()  # Treat window close as logout

if __name__ == "__main__":
    # This file is meant to be imported, not run standalone
    pass