import sys
import psutil
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import csv
from collections import defaultdict
from performance import PerformanceAnalyzerGUI
from graph import ProcessGraph
from ai_ml_integration import AIMLIntegrationGUI
from file_access import FileAccessGUI  # Import file_access.py
import random  # Added import for OTP generation

class SecurityLogger:
    def __init__(self, root):
        self.root = root
        self.root.title("Real Time OS Security Event Logger")
        self.root.state('zoomed')
        
        self.logs = []
        self.process_history = defaultdict(list)
        self.anomaly_threshold = 5
        
        self.canvas = tk.Canvas(root, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Configure>", self.update_gradient)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Dark.TLabel", background="#16213e", foreground="white", font=("Helvetica", 10))
        style.configure("Header.TLabel", background="#16213e", foreground="#00d4ff", font=("Helvetica", 16, "bold"))
        style.configure("Status.TLabel", background="#0f3460", foreground="#e94560", font=("Helvetica", 10, "italic"))
        
        main_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=main_frame, anchor="nw")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        header = ttk.Label(main_frame, text="Security Event Logger", style="Header.TLabel")
        header.pack(pady=(10, 20))
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(control_frame, text="Filter:", style="Dark.TLabel").pack(side=tk.LEFT, padx=10)
        self.filter_var = tk.StringVar(value="All Events")
        filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var, 
                                   values=["All Events", "INFO", "WARNING", "CRITICAL"], 
                                   state="readonly", width=15)
        filter_combo.pack(side=tk.LEFT, padx=10)
        filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)
        
        button_style = {"font": ("Helvetica", 11, "bold"), "relief": "flat", "bd": 0, "width": 18, "pady": 5}
        
        export_btn = tk.Button(control_frame, text="Export Logs", command=self.export_logs, bg="#00d4ff", fg="white", **button_style)
        export_btn.pack(side=tk.LEFT, padx=10)
        export_btn.bind("<Enter>", lambda e: export_btn.config(bg="#00b4d8"))
        export_btn.bind("<Leave>", lambda e: export_btn.config(bg="#00d4ff"))
        
        clear_btn = tk.Button(control_frame, text="Clear Logs", command=self.clear_logs, bg="#e94560", fg="white", **button_style)
        clear_btn.pack(side=tk.LEFT, padx=10)
        clear_btn.bind("<Enter>", lambda e: clear_btn.config(bg="#d62828"))
        clear_btn.bind("<Leave>", lambda e: clear_btn.config(bg="#e94560"))
        
        terminate_btn = tk.Button(control_frame, text="Terminate Process", command=self.terminate_process, bg="#f8a51d", fg="white", **button_style)
        terminate_btn.pack(side=tk.LEFT, padx=10)
        terminate_btn.bind("<Enter>", lambda e: terminate_btn.config(bg="#e07c10"))
        terminate_btn.bind("<Leave>", lambda e: terminate_btn.config(bg="#f8a51d"))
        
        perf_btn = tk.Button(control_frame, text="Performance Analysis", command=self.show_performance_analysis, bg="#2ecc71", fg="white", **button_style)
        perf_btn.pack(side=tk.LEFT, padx=10)
        perf_btn.bind("<Enter>", lambda e: perf_btn.config(bg="#27ae60"))
        perf_btn.bind("<Leave>", lambda e: perf_btn.config(bg="#2ecc71"))
        
        graph_btn = tk.Button(control_frame, text="Show Process Graph", command=self.show_process_graph, bg="#9b59b6", fg="white", **button_style)
        graph_btn.pack(side=tk.LEFT, padx=10)
        graph_btn.bind("<Enter>", lambda e: graph_btn.config(bg="#8e44ad"))
        graph_btn.bind("<Leave>", lambda e: graph_btn.config(bg="#9b59b6"))
        
        ai_ml_btn = tk.Button(control_frame, text="Show AI/ML Analysis", command=self.show_ai_ml_analysis, bg="#3498db", fg="white", **button_style)
        ai_ml_btn.pack(side=tk.LEFT, padx=10)
        ai_ml_btn.bind("<Enter>", lambda e: ai_ml_btn.config(bg="#2980b9"))
        ai_ml_btn.bind("<Leave>", lambda e: ai_ml_btn.config(bg="#3498db"))
        
        # New Secure File Access Button
        auth_btn = tk.Button(control_frame, text="Secure File Access", command=self.show_auth_system, bg="#e67e22", fg="white", **button_style)
        auth_btn.pack(side=tk.LEFT, padx=10)
        auth_btn.bind("<Enter>", lambda e: auth_btn.config(bg="#d35400"))
        auth_btn.bind("<Leave>", lambda e: auth_btn.config(bg="#e67e22"))
        
        spacer = ttk.Frame(control_frame)
        spacer.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        log_frame = tk.Frame(main_frame, bg="#1e1e1e", bd=2, relief="groove")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_display = scrolledtext.ScrolledText(log_frame, height=20, bg="#1e1e1e", fg="#ffffff", 
                                                    font=("Consolas", 10), insertbackground="white")
        self.log_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.status_var = tk.StringVar(value="Monitoring system events...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, style="Status.TLabel", anchor="center")
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        self.monitor_system()
    
    def update_gradient(self, event):
        width = event.width
        height = event.height
        self.canvas.delete("gradient")
        self.canvas.create_rectangle(0, 0, width, height, fill="#1a1a2e", outline="#1a1a2e", tags="gradient")
        self.canvas.create_rectangle(0, 0, width, height // 2, fill="#16213e", outline="#16213e", tags="gradient")
    
    def monitor_system(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    name = proc.info['name']
                    cpu_percent = proc.info['cpu_percent'] or 0
                    memory_percent = proc.info['memory_percent'] or 0
                    pid = proc.info['pid']
                    
                    if name not in self.process_history:
                        self.process_history[name] = []
                    
                    self.process_history[name].append({'time': current_time, 'cpu': cpu_percent, 'memory': memory_percent})
                    
                    if len(self.process_history[name]) > self.anomaly_threshold:
                        recent_usage = [p['cpu'] for p in self.process_history[name][-self.anomaly_threshold:]]
                        if max(recent_usage) > 80:
                            self.log_event(f"CRITICAL: High CPU usage detected for {name} (PID: {pid})", "CRITICAL")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > 80 or memory_percent > 80:
                self.log_event(f"WARNING: High system resource usage detected (CPU: {cpu_percent}%, Memory: {memory_percent}%)", "WARNING")
        
        except Exception as e:
            self.log_event(f"CRITICAL: Error monitoring system: {str(e)}", "CRITICAL")
        
        self.root.after(1000, self.monitor_system)
    
    def log_event(self, event, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {event}"
        self.logs.append((log_entry, level))
        self.log_display.insert(tk.END, log_entry + '\n')
        self.log_display.see(tk.END)
    
    def filter_logs(self, event=None):
        self.log_display.delete('1.0', tk.END)
        filter_text = self.filter_var.get()
        for log, level in self.logs:
            if filter_text == "All Events" or level == filter_text:
                self.log_display.insert(tk.END, log + '\n')
    
    def export_logs(self):
        file_name = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], title="Export Logs")
        if file_name:
            try:
                with open(file_name, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Timestamp', 'Severity', 'Event'])
                    for log, level in self.logs:
                        timestamp = log[1:20]
                        event = log[22:]
                        writer.writerow([timestamp, level, event])
                messagebox.showinfo("Success", "Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def clear_logs(self):
        self.logs.clear()
        self.log_display.delete('1.0', tk.END)
        self.status_var.set("Logs cleared")
    
    def terminate_process(self):
        pid = simpledialog.askinteger("Terminate Process", "Enter Process ID (PID) to terminate:")
        if pid:
            try:
                psutil.Process(pid).terminate()
                self.log_event(f"WARNING: Process {pid} terminated successfully.", "WARNING")
            except Exception as e:
                self.log_event(f"CRITICAL: Failed to terminate process {pid}: {str(e)}", "CRITICAL")
    
    def show_performance_analysis(self):
        perf_window = tk.Toplevel(self.root)
        PerformanceAnalyzerGUI(perf_window)
    
    def show_process_graph(self):
        graph_window = tk.Toplevel(self.root)
        ProcessGraph(graph_window)
    
    def show_ai_ml_analysis(self):
        ai_ml_window = tk.Toplevel(self.root)
        AIMLIntegrationGUI(ai_ml_window, self.process_history)
    
    def show_auth_system(self):
        auth_window = tk.Toplevel(self.root)
        AuthSystemGUI(auth_window, self.root)  # Pass the main root for reopening

# Integrated AuthSystem from auth_system.py
class AuthSystem:
    def __init__(self):
        self.users = {}
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
        self.otp = str(random.randint(100000, 999999))  # Now works with random imported
        self.otp_expiry = time.time() + 60
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
    def __init__(self, root, main_root):
        self.root = root
        self.main_root = main_root  # Reference to the main window root
        self.root.title("Secure Login System")
        self.root.geometry("800x600")
        self.auth = AuthSystem()

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

        header = ttk.Label(main_frame, text="Secure Login System", style="Header.TLabel")
        header.pack(pady=(10, 20))

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        register_frame = ttk.Frame(notebook)
        notebook.add(register_frame, text="Register")
        self.setup_register_tab(register_frame)

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
        file_window = tk.Toplevel(self.main_root)
        FileAccessGUI(file_window, self.auth, self.main_root)
        self.root.withdraw()  # Hide the login window

if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityLogger(root)
    root.mainloop()