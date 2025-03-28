import psutil
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time

class PerformanceAnalyzerGUI:
    def __init__(self, root, log_interval=5, log_file="performance_logs.csv", update_interval=60):
        self.root = root
        self.log_interval = log_interval
        self.log_file = log_file
        self.update_interval = update_interval
        self.selected_pid = None
        
        self.root.title("Performance Analyzer")
        self.root.geometry("1000x500")
        
        self.log_display = scrolledtext.ScrolledText(root, height=10, bg='#1e1e1e', fg='white')
        self.log_display.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.tree = ttk.Treeview(root, columns=("PID", "Name", "CPU%", "Memory%", "Threads", "User", "Start Time"), show='headings')
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="Process Name")
        self.tree.heading("CPU%", text="CPU Usage (%)")
        self.tree.heading("Memory%", text="Memory Usage (%)")
        self.tree.heading("Threads", text="Threads")
        self.tree.heading("User", text="User")
        self.tree.heading("Start Time", text="Start Time")
        self.tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.tree.bind("<ButtonRelease-1>", self.on_process_select)
        
        self.selected_label = ttk.Label(root, text="Selected Process: None")
        self.selected_label.pack(pady=5)
        
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=5)
        
        self.action_var = tk.StringVar(value="Terminate")
        action_menu = ttk.Combobox(button_frame, textvariable=self.action_var, values=["Terminate", "Kill"], state="readonly")
        action_menu.pack(side=tk.LEFT, padx=5)
        
        self.action_button = tk.Button(button_frame, text="Execute Action", command=self.execute_action, bg="red", fg="white")
        self.action_button.pack(side=tk.LEFT, padx=5)
        
        self.start_logging()
    
    def log_performance(self):
        while True:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cpu_usage = psutil.cpu_percent()
            memory_usage = psutil.virtual_memory().percent
            
            with open(self.log_file, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([timestamp, cpu_usage, memory_usage])
            
            log_entry = f"[{timestamp}] CPU: {cpu_usage}%, Memory: {memory_usage}%\n"
            self.log_display.insert(tk.END, log_entry)
            self.log_display.see(tk.END)
            
            self.update_process_list()
            time.sleep(self.update_interval)
    
    def update_process_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'username', 'create_time']):
            try:
                start_time = datetime.fromtimestamp(proc.info['create_time']).strftime('%H:%M:%S')
                self.tree.insert("", tk.END, values=(proc.info['pid'], proc.info['name'], proc.info['cpu_percent'], proc.info['memory_percent'], proc.info['num_threads'], proc.info['username'], start_time))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    
    def on_process_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            self.selected_pid = self.tree.item(selected_item)['values'][0]
            process_name = self.tree.item(selected_item)['values'][1]
            self.selected_label.config(text=f"Selected Process: {process_name} (PID: {self.selected_pid})")
    
    def execute_action(self):
        if self.selected_pid:
            action = self.action_var.get()
            confirm = messagebox.askyesno("Confirm Action", f"Are you sure you want to {action.lower()} process {self.selected_pid}?")
            if confirm:
                try:
                    proc = psutil.Process(self.selected_pid)
                    if action == "Terminate":
                        proc.terminate()
                        messagebox.showinfo("Success", f"Process {self.selected_pid} terminated successfully!")
                    else:
                        proc.kill()
                        messagebox.showinfo("Success", f"Process {self.selected_pid} forcefully killed!")
                    self.update_process_list()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to {action.lower()} process {self.selected_pid}: {str(e)}")
        else:
            messagebox.showwarning("Warning", "Please select a process first.")
    
    def start_logging(self):
        threading.Thread(target=self.log_performance, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = PerformanceAnalyzerGUI(root)
    root.mainloop()
