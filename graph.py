# graph.py
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import psutil
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk

class ProcessGraph:
    def __init__(self, root):
        self.root = root
        self.root.title("Top 10 Processes CPU Usage Graph")
        self.root.geometry("1000x700")
        
        # Data storage
        self.process_data = {}  # {pid: {'name': str, 'times': [], 'cpu': []}}
        self.max_points = 50  # Limit to 50 data points per process
        self.selected_pid = None
        
        # Colors for the top 10 processes
        self.colors = ["#00d4ff", "#e94560", "#f8a51d", "#2ecc71", "#9b59b6", 
                      "#3498db", "#e74c3c", "#f1c40f", "#1abc9c", "#8e44ad"]
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Dropdown for process selection
        self.select_var = tk.StringVar(value="Select a Process")
        self.process_dropdown = ttk.Combobox(main_frame, textvariable=self.select_var, state="readonly")
        self.process_dropdown.pack(pady=5)
        self.process_dropdown.bind("<<ComboboxSelected>>", self.on_process_select)
        
        # Create figure and axis
        self.fig, self.ax = plt.subplots(figsize=(10, 5))
        self.ax.set_title("Top 10 Processes CPU Usage Over Time", fontsize=14, pad=10)
        self.ax.set_xlabel("Time", fontsize=12)
        self.ax.set_ylabel("CPU Usage (%)", fontsize=12)
        self.ax.grid(True, linestyle='--', alpha=0.7)
        
        # Initialize empty lines for top 10 processes
        self.lines = {}
        
        # Embed plot in Tkinter window
        self.canvas = FigureCanvasTkAgg(self.fig, master=main_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Start updating
        self.update_graph()
        
    def update_graph(self):
        """Update the graph with CPU usage for top 10 processes."""
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # Get current process data
        process_list = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cpu = proc.info['cpu_percent'] or 0
                if pid not in self.process_data:
                    self.process_data[pid] = {'name': name, 'times': [], 'cpu': []}
                process_list.append((pid, cpu))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort by CPU usage and take top 10
        top_10 = sorted(process_list, key=lambda x: x[1], reverse=True)[:10]
        top_pids = [pid for pid, _ in top_10]
        
        # Update data for top 10 processes
        for pid, cpu in top_10:
            self.process_data[pid]['times'].append(current_time)
            self.process_data[pid]['cpu'].append(cpu)
            if len(self.process_data[pid]['times']) > self.max_points:
                self.process_data[pid]['times'].pop(0)
                self.process_data[pid]['cpu'].pop(0)
        
        # Update dropdown options
        dropdown_options = [f"{self.process_data[pid]['name']} (PID: {pid})" for pid in top_pids]
        self.process_dropdown['values'] = dropdown_options
        if not self.select_var.get() in dropdown_options and dropdown_options:
            self.select_var.set(dropdown_options[0])  # Default to first process
        
        # Clear previous lines
        self.ax.clear()
        self.ax.set_title("Top 10 Processes CPU Usage Over Time", fontsize=14, pad=10)
        self.ax.set_xlabel("Time", fontsize=12)
        self.ax.set_ylabel("CPU Usage (%)", fontsize=12)
        self.ax.grid(True, linestyle='--', alpha=0.7)
        
        # Plot lines for top 10 processes
        self.lines.clear()
        for i, pid in enumerate(top_pids):
            times = self.process_data[pid]['times']
            cpu_data = self.process_data[pid]['cpu']
            name = self.process_data[pid]['name']
            linewidth = 2.5 if pid == self.selected_pid else 1.0  # Highlight selected process
            self.lines[pid], = self.ax.plot(range(len(times)), cpu_data, label=f"{name} (PID: {pid})", 
                                           color=self.colors[i % len(self.colors)], linewidth=linewidth)
        
        # Update axis limits (handle empty data case)
        if top_pids and self.process_data[top_pids[0]]['times']:
            self.ax.set_xlim(0, len(self.process_data[top_pids[0]]['times']) - 1)
            # Find the maximum CPU value across all top 10 processes
            max_cpu = max([max(self.process_data[pid]['cpu']) for pid in top_pids if self.process_data[pid]['cpu']], default=0)
            self.ax.set_ylim(0, max(max_cpu, 100))  # Ensure at least 100% range
            self.ax.set_xticks(range(0, len(self.process_data[top_pids[0]]['times']), 
                                   max(1, len(self.process_data[top_pids[0]]['times']) // 5)))
            self.ax.set_xticklabels(self.process_data[top_pids[0]]['times'][::max(1, len(self.process_data[top_pids[0]]['times']) // 5)], 
                                  rotation=45, ha="right")
        else:
            self.ax.set_xlim(0, 1)  # Default range for empty data
            self.ax.set_ylim(0, 100)
            self.ax.set_xticks([])
            self.ax.set_xticklabels([])
        
        self.ax.legend(loc="upper right", fontsize=8)
        self.canvas.draw()
        
        # Schedule next update (every 2 seconds)
        self.root.after(2000, self.update_graph)
    
    def on_process_select(self, event):
        """Highlight the selected process in the graph."""
        selected_text = self.select_var.get()
        if "PID: " in selected_text:
            pid_str = selected_text.split("PID: ")[1].rstrip(")")
            self.selected_pid = int(pid_str)
            self.update_graph()  # Redraw to highlight the selected process

if __name__ == "__main__":
    root = tk.Tk()
    app = ProcessGraph(root)
    root.mainloop()