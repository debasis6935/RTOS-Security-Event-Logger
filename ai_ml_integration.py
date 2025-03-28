# ai_ml_integration.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from statsmodels.tsa.arima.model import ARIMA
import tkinter as tk
from tkinter import ttk, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime  # Added import
import warnings
warnings.filterwarnings("ignore")  # Suppress ARIMA warnings

class AIMLIntegrationGUI:
    def __init__(self, root, process_history):
        self.root = root
        self.root.title("AI & ML System Analysis")
        self.root.geometry("1000x700")
        self.process_history = process_history
        
        # AI/ML Models
        self.anomaly_model = IsolationForest(contamination=0.1, random_state=42)
        self.threat_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        
        # GUI Setup
        self.setup_gui()
        
        # Train models initially
        self.train_models()
        self.update_display()
        
    def setup_gui(self):
        """Set up the GUI layout."""
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tabs for different features
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Anomaly Detection Tab
        anomaly_frame = ttk.Frame(notebook)
        notebook.add(anomaly_frame, text="Anomaly Detection")
        self.anomaly_text = scrolledtext.ScrolledText(anomaly_frame, height=20, bg="#1e1e1e", fg="white", font=("Consolas", 10))
        self.anomaly_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Predictive Analysis Tab
        predict_frame = ttk.Frame(notebook)
        notebook.add(predict_frame, text="Predictive Analysis")
        self.fig, self.ax = plt.subplots(figsize=(8, 4))
        self.predict_canvas = FigureCanvasTkAgg(self.fig, master=predict_frame)
        self.predict_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threat Classification Tab
        threat_frame = ttk.Frame(notebook)
        notebook.add(threat_frame, text="Threat Classification")
        self.threat_text = scrolledtext.ScrolledText(threat_frame, height=20, bg="#1e1e1e", fg="white", font=("Consolas", 10))
        self.threat_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Refresh", command=self.update_display).pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="AI/ML Analysis Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, anchor="center")
        status_bar.pack(fill=tk.X)
        
    def prepare_data(self):
        """Prepare data from process_history for ML models."""
        data = []
        for name, history in self.process_history.items():
            for entry in history:
                data.append({
                    'name': name,
                    'cpu': entry['cpu'],
                    'memory': entry['memory'],
                    'time': entry['time']
                })
        df = pd.DataFrame(data)
        return df
    
    def train_anomaly_model(self):
        """Train the anomaly detection model."""
        df = self.prepare_data()
        if df.empty:
            return False
        X = df[['cpu', 'memory']].values
        self.anomaly_model.fit(X)
        return True
    
    def detect_anomalies(self):
        """Detect anomalies in the latest process data."""
        df = self.prepare_data()
        if df.empty or not hasattr(self.anomaly_model, 'predict'):
            return {}
        X = df[['cpu', 'memory']].values
        predictions = self.anomaly_model.predict(X)
        anomalies = {}
        for idx, pred in enumerate(predictions):
            if pred == -1:
                pid = df.iloc[idx]['name']
                anomalies[pid] = {'cpu': df.iloc[idx]['cpu'], 'memory': df.iloc[idx]['memory']}
        return anomalies
    
    def train_threat_model(self):
        """Train the threat classification model with dummy labels."""
        df = self.prepare_data()
        if df.empty:
            return False
        df['label'] = np.where((df['cpu'] > 80) | (df['memory'] > 80), 1, 0)  # Dummy labels
        X = df[['cpu', 'memory']].values
        process_names = self.label_encoder.fit_transform(df['name'])
        X = np.column_stack((X, process_names))
        y = df['label'].values
        self.threat_model.fit(X, y)
        self.is_trained = True
        return True
    
    def classify_threats(self):
        """Classify processes as safe (0) or malicious (1)."""
        df = self.prepare_data()
        if df.empty or not self.is_trained:
            return {}
        X = df[['cpu', 'memory']].values
        process_names = self.label_encoder.transform(df['name'])
        X = np.column_stack((X, process_names))
        predictions = self.threat_model.predict(X)
        threats = {}
        for idx, pred in enumerate(predictions):
            if pred == 1:
                pid = df.iloc[idx]['name']
                threats[pid] = {'cpu': df.iloc[idx]['cpu'], 'memory': df.iloc[idx]['memory']}
        return threats
    
    def predict_system_load(self, metric='cpu', steps=5):
        """Predict future system load using ARIMA."""
        df = self.prepare_data()
        if df.empty:
            return None
        system_data = df.groupby('time').agg({'cpu': 'mean', 'memory': 'mean'}).reset_index()
        series = system_data[metric].values
        if len(series) < 10:
            return None
        model = ARIMA(series, order=(1, 1, 1))
        model_fit = model.fit()
        forecast = model_fit.forecast(steps=steps)
        return series[-10:].tolist(), forecast.tolist()  # Return last 10 points + forecast
    
    def train_models(self):
        """Train all models at startup."""
        self.train_anomaly_model()
        self.train_threat_model()
        self.status_var.set("Models trained successfully")
    
    def update_display(self):
        """Update the GUI with the latest analysis."""
        # Anomaly Detection
        self.anomaly_text.delete('1.0', tk.END)
        anomalies = self.detect_anomalies()
        if anomalies:
            self.anomaly_text.insert(tk.END, "Detected Anomalies:\n")
            for pid, data in anomalies.items():
                self.anomaly_text.insert(tk.END, f"Process: {pid}, CPU: {data['cpu']}%, Memory: {data['memory']}%\n")
        else:
            self.anomaly_text.insert(tk.END, "No anomalies detected.\n")
        
        # Predictive Analysis
        self.ax.clear()
        self.ax.set_title("System CPU Load Prediction", fontsize=14)
        self.ax.set_xlabel("Time Steps", fontsize=12)
        self.ax.set_ylabel("CPU Usage (%)", fontsize=12)
        self.ax.grid(True, linestyle='--', alpha=0.7)
        forecast_data = self.predict_system_load(metric='cpu', steps=5)
        if forecast_data:
            past, future = forecast_data
            total_steps = list(range(len(past) + len(future)))
            past_steps = total_steps[:len(past)]
            future_steps = total_steps[len(past):]
            self.ax.plot(past_steps, past, label="Past CPU", color="#00d4ff")
            self.ax.plot(future_steps, future, label="Forecasted CPU", color="#e94560", linestyle='--')
            self.ax.legend(loc="upper right")
        else:
            self.ax.text(0.5, 0.5, "Insufficient data for prediction", ha='center', va='center')
        self.predict_canvas.draw()
        
        # Threat Classification
        self.threat_text.delete('1.0', tk.END)
        threats = self.classify_threats()
        if threats:
            self.threat_text.insert(tk.END, "Potential Threats:\n")
            for pid, data in threats.items():
                self.threat_text.insert(tk.END, f"Process: {pid}, CPU: {data['cpu']}%, Memory: {data['memory']}%\n")
        else:
            self.threat_text.insert(tk.END, "No threats detected.\n")
        
        self.status_var.set("Analysis updated at " + datetime.now().strftime("%H:%M:%S"))

if __name__ == "__main__":
    # Demo usage with dummy data
    dummy_history = {
        'process1.exe': [{'time': f'2025-03-27 10:00:{i:02d}', 'cpu': 10.0 + i, 'memory': 5.0 + i} for i in range(15)],
        'process2.exe': [{'time': f'2025-03-27 10:00:{i:02d}', 'cpu': 90.0 + i, 'memory': 85.0 + i} for i in range(15)]
    }
    root = tk.Tk()
    app = AIMLIntegrationGUI(root, dummy_history)
    root.mainloop()