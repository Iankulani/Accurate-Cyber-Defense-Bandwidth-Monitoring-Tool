#!/usr/bin/env python3
"""
Cybersecurity Bandwidth Monitoring Tool
A comprehensive network monitoring application with purple-themed GUI
Monitors bandwidth usage for specified IP addresses with real-time visualization
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading
import time
import json
import os
import socket
import struct
import psutil
import netifaces
from datetime import datetime, timedelta
import ipaddress
from collections import defaultdict, deque
import numpy as np
import sqlite3
from typing import Dict, List, Tuple, Optional
import logging
import queue
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bandwidth_monitor.log'),
        logging.StreamHandler()
    ]
)

class DatabaseManager:
    """Manages SQLite database operations for storing bandwidth data"""
    
    def __init__(self, db_path: str = "bandwidth_data.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bandwidth_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT NOT NULL,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    packets_sent INTEGER DEFAULT 0,
                    packets_received INTEGER DEFAULT 0,
                    connection_type TEXT DEFAULT 'unknown'
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitored_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    description TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    added_date DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logging.info("Database initialized successfully")
        except Exception as e:
            logging.error(f"Database initialization error: {e}")
    
    def add_bandwidth_log(self, ip_address: str, bytes_sent: int, bytes_received: int, 
                         packets_sent: int, packets_received: int, connection_type: str = "unknown"):
        """Add bandwidth log entry"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO bandwidth_logs 
                (ip_address, bytes_sent, bytes_received, packets_sent, packets_received, connection_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip_address, bytes_sent, bytes_received, packets_sent, packets_received, connection_type))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Error adding bandwidth log: {e}")
    
    def get_bandwidth_data(self, ip_address: str = None, hours: int = 24) -> List[Tuple]:
        """Retrieve bandwidth data from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since_time = datetime.now() - timedelta(hours=hours)
            
            if ip_address:
                cursor.execute('''
                    SELECT * FROM bandwidth_logs 
                    WHERE ip_address = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                ''', (ip_address, since_time))
            else:
                cursor.execute('''
                    SELECT * FROM bandwidth_logs 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (since_time,))
            
            data = cursor.fetchall()
            conn.close()
            return data
        except Exception as e:
            logging.error(f"Error retrieving bandwidth data: {e}")
            return []

class NetworkMonitor:
    """Core network monitoring functionality"""
    
    def __init__(self):
        self.monitoring = False
        self.monitored_ips = set()
        self.bandwidth_data = defaultdict(lambda: {"sent": deque(maxlen=100), "received": deque(maxlen=100)})
        self.packet_data = defaultdict(lambda: {"sent": deque(maxlen=100), "received": deque(maxlen=100)})
        self.db_manager = DatabaseManager()
        self.data_queue = queue.Queue()
        
    def add_ip_to_monitor(self, ip_address: str) -> bool:
        """Add IP address to monitoring list"""
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            self.monitored_ips.add(ip_address)
            logging.info(f"Added IP {ip_address} to monitoring list")
            return True
        except ValueError:
            logging.error(f"Invalid IP address: {ip_address}")
            return False
    
    def remove_ip_from_monitor(self, ip_address: str):
        """Remove IP address from monitoring list"""
        self.monitored_ips.discard(ip_address)
        logging.info(f"Removed IP {ip_address} from monitoring list")
    
    def get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        try:
            return list(netifaces.interfaces())
        except Exception as e:
            logging.error(f"Error getting network interfaces: {e}")
            return []
    
    def get_network_stats(self) -> Dict:
        """Get current network statistics"""
        try:
            stats = psutil.net_io_counters(pernic=True)
            return stats
        except Exception as e:
            logging.error(f"Error getting network stats: {e}")
            return {}
    
    def simulate_ip_traffic(self, ip_address: str) -> Tuple[int, int, int, int]:
        """Simulate traffic data for specific IP address"""
        # In a real implementation, this would capture actual network packets
        # For demonstration, we'll simulate realistic bandwidth data
        base_sent = np.random.randint(1024, 10240)  # 1KB to 10KB
        base_received = np.random.randint(2048, 20480)  # 2KB to 20KB
        packets_sent = np.random.randint(10, 100)
        packets_received = np.random.randint(15, 150)
        
        # Add some variability based on IP
        ip_hash = hash(ip_address) % 1000
        multiplier = 1 + (ip_hash / 1000)
        
        bytes_sent = int(base_sent * multiplier)
        bytes_received = int(base_received * multiplier)
        
        return bytes_sent, bytes_received, packets_sent, packets_received
    
    def start_monitoring(self):
        """Start the monitoring process"""
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        logging.info("Network monitoring started")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.monitoring = False
        logging.info("Network monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                for ip_address in self.monitored_ips.copy():
                    bytes_sent, bytes_received, packets_sent, packets_received = self.simulate_ip_traffic(ip_address)
                    
                    # Store data in memory for real-time display
                    self.bandwidth_data[ip_address]["sent"].append(bytes_sent)
                    self.bandwidth_data[ip_address]["received"].append(bytes_received)
                    self.packet_data[ip_address]["sent"].append(packets_sent)
                    self.packet_data[ip_address]["received"].append(packets_received)
                    
                    # Store in database
                    self.db_manager.add_bandwidth_log(
                        ip_address, bytes_sent, bytes_received, 
                        packets_sent, packets_received, "ethernet"
                    )
                    
                    # Send data to GUI
                    self.data_queue.put({
                        'ip': ip_address,
                        'bytes_sent': bytes_sent,
                        'bytes_received': bytes_received,
                        'packets_sent': packets_sent,
                        'packets_received': packets_received,
                        'timestamp': datetime.now()
                    })
                
                time.sleep(2)  # Monitor every 2 seconds
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
                time.sleep(1)

class BandwidthAnalyzer:
    """Analyzes bandwidth data and generates statistics"""
    
    def __init__(self, network_monitor: NetworkMonitor):
        self.monitor = network_monitor
    
    def get_total_bandwidth(self, ip_address: str) -> Tuple[int, int]:
        """Get total bandwidth for an IP address"""
        data = self.monitor.bandwidth_data.get(ip_address, {"sent": deque(), "received": deque()})
        total_sent = sum(data["sent"])
        total_received = sum(data["received"])
        return total_sent, total_received
    
    def get_average_bandwidth(self, ip_address: str) -> Tuple[float, float]:
        """Get average bandwidth for an IP address"""
        data = self.monitor.bandwidth_data.get(ip_address, {"sent": deque(), "received": deque()})
        if not data["sent"] or not data["received"]:
            return 0.0, 0.0
        
        avg_sent = sum(data["sent"]) / len(data["sent"])
        avg_received = sum(data["received"]) / len(data["received"])
        return avg_sent, avg_received
    
    def get_peak_bandwidth(self, ip_address: str) -> Tuple[int, int]:
        """Get peak bandwidth for an IP address"""
        data = self.monitor.bandwidth_data.get(ip_address, {"sent": deque(), "received": deque()})
        if not data["sent"] or not data["received"]:
            return 0, 0
        
        peak_sent = max(data["sent"])
        peak_received = max(data["received"])
        return peak_sent, peak_received
    
    def get_bandwidth_trend(self, ip_address: str) -> Dict:
        """Analyze bandwidth trend for an IP address"""
        data = self.monitor.bandwidth_data.get(ip_address, {"sent": deque(), "received": deque()})
        if len(data["sent"]) < 2:
            return {"trend": "insufficient_data", "slope": 0}
        
        # Simple linear regression for trend analysis
        sent_data = list(data["sent"])
        x = list(range(len(sent_data)))
        
        if len(x) > 1:
            slope = np.polyfit(x, sent_data, 1)[0]
            if slope > 0:
                trend = "increasing"
            elif slope < 0:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "stable"
            slope = 0
        
        return {"trend": trend, "slope": slope}

class PurpleTheme:
    """Purple theme configuration for the GUI"""
    
    # Primary colors
    PRIMARY_PURPLE = "#6A0DAD"
    LIGHT_PURPLE = "#9370DB"
    DARK_PURPLE = "#4B0082"
    VERY_LIGHT_PURPLE = "#E6E6FA"
    
    # Background colors
    BG_MAIN = "#2E1065"
    BG_SECONDARY = "#3D1A78"
    BG_TERTIARY = "#4B208B"
    
    # Text colors
    TEXT_PRIMARY = "#FFFFFF"
    TEXT_SECONDARY = "#E6E6FA"
    TEXT_ACCENT = "#DDA0DD"
    
    # Chart colors
    CHART_COLORS = ["#8A2BE2", "#9370DB", "#BA55D3", "#DA70D6", "#DDA0DD", "#E6E6FA"]
    
    @classmethod
    def configure_style(cls):
        """Configure ttk styles with purple theme"""
        style = ttk.Style()
        
        # Configure frame styles
        style.configure("Purple.TFrame", background=cls.BG_MAIN)
        style.configure("PurpleLight.TFrame", background=cls.BG_SECONDARY)
        
        # Configure label styles
        style.configure("Purple.TLabel", 
                       background=cls.BG_MAIN, 
                       foreground=cls.TEXT_PRIMARY,
                       font=("Arial", 10))
        
        style.configure("PurpleTitle.TLabel", 
                       background=cls.BG_MAIN, 
                       foreground=cls.TEXT_PRIMARY,
                       font=("Arial", 14, "bold"))
        
        # Configure button styles
        style.configure("Purple.TButton",
                       background=cls.PRIMARY_PURPLE,
                       foreground=cls.TEXT_PRIMARY,
                       font=("Arial", 10, "bold"))
        
        style.map("Purple.TButton",
                 background=[("active", cls.LIGHT_PURPLE)])
        
        # Configure entry styles
        style.configure("Purple.TEntry",
                       fieldbackground=cls.VERY_LIGHT_PURPLE,
                       foreground=cls.DARK_PURPLE,
                       font=("Arial", 10))
        
        return style

class ChartManager:
    """Manages chart creation and updates"""
    
    def __init__(self, theme: PurpleTheme):
        self.theme = theme
        plt.style.use('dark_background')
    
    def create_bandwidth_bar_chart(self, data: Dict, title: str = "Bandwidth Usage") -> Figure:
        """Create a bar chart for bandwidth data"""
        fig, ax = plt.subplots(figsize=(10, 6), facecolor=self.theme.BG_MAIN)
        ax.set_facecolor(self.theme.BG_SECONDARY)
        
        if not data:
            ax.text(0.5, 0.5, 'No data available', 
                   transform=ax.transAxes, ha='center', va='center',
                   color=self.theme.TEXT_PRIMARY, fontsize=14)
            ax.set_title(title, color=self.theme.TEXT_PRIMARY, fontsize=16, fontweight='bold')
            return fig
        
        ips = list(data.keys())
        sent_data = [sum(data[ip]["sent"]) for ip in ips]
        received_data = [sum(data[ip]["received"]) for ip in ips]
        
        x = np.arange(len(ips))
        width = 0.35
        
        bars1 = ax.bar(x - width/2, sent_data, width, label='Sent', 
                      color=self.theme.CHART_COLORS[0], alpha=0.8)
        bars2 = ax.bar(x + width/2, received_data, width, label='Received', 
                      color=self.theme.CHART_COLORS[1], alpha=0.8)
        
        ax.set_xlabel('IP Addresses', color=self.theme.TEXT_PRIMARY, fontweight='bold')
        ax.set_ylabel('Bytes', color=self.theme.TEXT_PRIMARY, fontweight='bold')
        ax.set_title(title, color=self.theme.TEXT_PRIMARY, fontsize=16, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(ips, rotation=45, ha='right', color=self.theme.TEXT_SECONDARY)
        ax.tick_params(colors=self.theme.TEXT_SECONDARY)
        ax.legend(facecolor=self.theme.BG_TERTIARY, edgecolor=self.theme.PRIMARY_PURPLE)
        
        # Add value labels on bars
        for bar in bars1:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height):,}', ha='center', va='bottom', 
                   color=self.theme.TEXT_PRIMARY)
        
        for bar in bars2:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height):,}', ha='center', va='bottom', 
                   color=self.theme.TEXT_PRIMARY)
        
        plt.tight_layout()
        return fig
    
    def create_bandwidth_pie_chart(self, data: Dict, title: str = "Bandwidth Distribution") -> Figure:
        """Create a pie chart for bandwidth data"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8), facecolor=self.theme.BG_MAIN)
        
        if not data:
            for ax in [ax1, ax2]:
                ax.text(0.5, 0.5, 'No data available', 
                       transform=ax.transAxes, ha='center', va='center',
                       color=self.theme.TEXT_PRIMARY, fontsize=14)
            ax1.set_title('Sent Data', color=self.theme.TEXT_PRIMARY, fontsize=14, fontweight='bold')
            ax2.set_title('Received Data', color=self.theme.TEXT_PRIMARY, fontsize=14, fontweight='bold')
            return fig
        
        ips = list(data.keys())
        sent_data = [sum(data[ip]["sent"]) for ip in ips]
        received_data = [sum(data[ip]["received"]) for ip in ips]
        
        # Sent data pie chart
        if sum(sent_data) > 0:
            wedges1, texts1, autotexts1 = ax1.pie(sent_data, labels=ips, autopct='%1.1f%%',
                                                  colors=self.theme.CHART_COLORS[:len(ips)],
                                                  startangle=90)
            for text in texts1:
                text.set_color(self.theme.TEXT_PRIMARY)
            for autotext in autotexts1:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
        
        ax1.set_title('Data Sent Distribution', color=self.theme.TEXT_PRIMARY, 
                     fontsize=14, fontweight='bold')
        
        # Received data pie chart
        if sum(received_data) > 0:
            wedges2, texts2, autotexts2 = ax2.pie(received_data, labels=ips, autopct='%1.1f%%',
                                                  colors=self.theme.CHART_COLORS[:len(ips)],
                                                  startangle=90)
            for text in texts2:
                text.set_color(self.theme.TEXT_PRIMARY)
            for autotext in autotexts2:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
        
        ax2.set_title('Data Received Distribution', color=self.theme.TEXT_PRIMARY, 
                     fontsize=14, fontweight='bold')
        
        plt.suptitle(title, color=self.theme.TEXT_PRIMARY, fontsize=16, fontweight='bold')
        plt.tight_layout()
        return fig

class CyberSecurityMonitorGUI:
    """Main GUI class for the cybersecurity monitoring tool"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Accurate Cyber Defense Bandwidth Monitoring Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg=PurpleTheme.BG_MAIN)
        
        # Initialize components
        self.theme = PurpleTheme()
        self.style = self.theme.configure_style()
        self.network_monitor = NetworkMonitor()
        self.analyzer = BandwidthAnalyzer(self.network_monitor)
        self.chart_manager = ChartManager(self.theme)
        
        # GUI variables
        self.ip_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.monitoring_active = tk.BooleanVar(value=False)
        
        # Data update tracking
        self.last_update = time.time()
        self.update_interval = 3000  # 3 seconds
        
        self.setup_gui()
        self.start_data_update_loop()
    
    def setup_gui(self):
        """Setup the main GUI components"""
        # Main container
        main_frame = ttk.Frame(self.root, style="Purple.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="🛡️ Accurate Cyber Defense Bandwidth Monitoring Tool", 
                               style="PurpleTitle.TLabel")
        title_label.pack(pady=(0, 20))
        
        # Control panel
        self.create_control_panel(main_frame)
        
        # Main content area with notebook
        self.create_main_content(main_frame)
        
        # Status bar
        self.create_status_bar(main_frame)
    
    def create_control_panel(self, parent):
        """Create the control panel for IP management"""
        control_frame = ttk.Frame(parent, style="PurpleLight.TFrame")
        control_frame.pack(fill=tk.X, pady=(0, 20))
        
        # IP input section
        ip_frame = ttk.Frame(control_frame, style="PurpleLight.TFrame")
        ip_frame.pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Label(ip_frame, text="IP Address:", style="Purple.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        
        ip_entry = ttk.Entry(ip_frame, textvariable=self.ip_var, width=15, style="Purple.TEntry")
        ip_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        add_btn = ttk.Button(ip_frame, text="Add IP", command=self.add_ip, style="Purple.TButton")
        add_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        remove_btn = ttk.Button(ip_frame, text="Remove IP", command=self.remove_ip, style="Purple.TButton")
        remove_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Monitoring control
        monitor_frame = ttk.Frame(control_frame, style="PurpleLight.TFrame")
        monitor_frame.pack(side=tk.LEFT, padx=10)
        
        self.monitor_btn = ttk.Button(monitor_frame, text="Start Monitoring", 
                                     command=self.toggle_monitoring, style="Purple.TButton")
        self.monitor_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        clear_btn = ttk.Button(monitor_frame, text="Clear Data", 
                              command=self.clear_data, style="Purple.TButton")
        clear_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        export_btn = ttk.Button(monitor_frame, text="Export Data", 
                               command=self.export_data, style="Purple.TButton")
        export_btn.pack(side=tk.LEFT)
    
    def create_main_content(self, parent):
        """Create the main content area with tabs"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Dashboard tab
        self.create_dashboard_tab(notebook)
        
        # Charts tab
        self.create_charts_tab(notebook)
        
        # Data table tab
        self.create_data_tab(notebook)
        
        # Logs tab
        self.create_logs_tab(notebook)
    
    def create_dashboard_tab(self, notebook):
        """Create the main dashboard tab"""
        dashboard_frame = ttk.Frame(notebook, style="Purple.TFrame")
        notebook.add(dashboard_frame, text="Dashboard")
        
        # Monitored IPs section
        ip_section = ttk.LabelFrame(dashboard_frame, text="Monitored IP Addresses", 
                                   style="Purple.TFrame")
        ip_section.pack(fill=tk.X, padx=10, pady=10)
        
        # IP listbox with scrollbar
        ip_listbox_frame = ttk.Frame(ip_section, style="Purple.TFrame")
        ip_listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.ip_listbox = tk.Listbox(ip_listbox_frame, height=6, 
                                    bg=self.theme.VERY_LIGHT_PURPLE,
                                    fg=self.theme.DARK_PURPLE,
                                    selectbackground=self.theme.PRIMARY_PURPLE,
                                    font=("Arial", 10))
        
        ip_scrollbar = ttk.Scrollbar(ip_listbox_frame, orient=tk.VERTICAL, 
                                    command=self.ip_listbox.yview)
        self.ip_listbox.configure(yscrollcommand=ip_scrollbar.set)
        
        self.ip_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ip_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statistics section
        stats_section = ttk.LabelFrame(dashboard_frame, text="Real-time Statistics", 
                                      style="Purple.TFrame")
        stats_section.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.stats_text = scrolledtext.ScrolledText(stats_section, height=15,
                                                   bg=self.theme.BG_SECONDARY,
                                                   fg=self.theme.TEXT_PRIMARY,
                                                   font=("Consolas", 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_charts_tab(self, notebook):
        """Create the charts visualization tab"""
        charts_frame = ttk.Frame(notebook, style="Purple.TFrame")
        notebook.add(charts_frame, text="Charts")
        
        # Chart controls
        chart_controls = ttk.Frame(charts_frame, style="Purple.TFrame")
        chart_controls.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(chart_controls, text="Update Bar Chart", 
                  command=self.update_bar_chart, style="Purple.TButton").pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(chart_controls, text="Update Pie Chart", 
                  command=self.update_pie_chart, style="Purple.TButton").pack(side=tk.LEFT, padx=(0, 5))
        
        # Chart display area
        self.chart_notebook = ttk.Notebook(charts_frame)
        self.chart_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Bar chart frame
        self.bar_chart_frame = ttk.Frame(self.chart_notebook, style="Purple.TFrame")
        self.chart_notebook.add(self.bar_chart_frame, text="Bar Chart")
        
        # Pie chart frame
        self.pie_chart_frame = ttk.Frame(self.chart_notebook, style="Purple.TFrame")
        self.chart_notebook.add(self.pie_chart_frame, text="Pie Chart")
        
        # Initialize charts
        self.bar_canvas = None
        self.pie_canvas = None
        self.update_bar_chart()
        self.update_pie_chart()
    
    def create_data_tab(self, notebook):
        """Create the data table tab"""
        data_frame = ttk.Frame(notebook, style="Purple.TFrame")
        notebook.add(data_frame, text="Data Table")
        
        # Data table
        columns = ('IP Address', 'Bytes Sent', 'Bytes Received', 'Packets Sent', 'Packets Received', 'Timestamp')
        self.data_tree = ttk.Treeview(data_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.data_tree.heading(col, text=col)
            self.data_tree.column(col, width=150)
        
        # Scrollbars for data table
        data_v_scrollbar = ttk.Scrollbar(data_frame, orient=tk.VERTICAL, command=self.data_tree.yview)
        data_h_scrollbar = ttk.Scrollbar(data_frame, orient=tk.HORIZONTAL, command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=data_v_scrollbar.set, xscrollcommand=data_h_scrollbar.set)
        
        self.data_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        data_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        data_h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X, padx=10)
    
    def create_logs_tab(self, notebook):
        """Create the system logs tab"""
        logs_frame = ttk.Frame(notebook, style="Purple.TFrame")
        notebook.add(logs_frame, text="System Logs")
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25,
                                                  bg=self.theme.BG_SECONDARY,
                                                  fg=self.theme.TEXT_PRIMARY,
                                                  font=("Consolas", 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Load existing logs
        self.load_system_logs()
    
    def create_status_bar(self, parent):
        """Create the status bar"""
        status_frame = ttk.Frame(parent, style="Purple.TFrame")
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(status_frame, text="Status:", style="Purple.TLabel").pack(side=tk.LEFT)
        
        status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                style="Purple.TLabel")
        status_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Connection indicator
        self.connection_indicator = tk.Label(status_frame, text="●", 
                                           fg="red", bg=self.theme.BG_MAIN,
                                           font=("Arial", 12))
        self.connection_indicator.pack(side=tk.RIGHT, padx=(0, 10))
        
        ttk.Label(status_frame, text="Connection:", style="Purple.TLabel").pack(side=tk.RIGHT)
    
    def add_ip(self):
        """Add IP address to monitoring list"""
        ip_address = self.ip_var.get().strip()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address")
            return
        
        if self.network_monitor.add_ip_to_monitor(ip_address):
            self.ip_listbox.insert(tk.END, ip_address)
            self.ip_var.set("")
            self.status_var.set(f"Added IP: {ip_address}")
            self.log_message(f"Successfully added IP {ip_address} to monitoring list")
        else:
            messagebox.showerror("Error", f"Invalid IP address: {ip_address}")
            self.status_var.set("Error: Invalid IP address")
    
    def remove_ip(self):
        """Remove selected IP from monitoring list"""
        selection = self.ip_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an IP address to remove")
            return
        
        index = selection[0]
        ip_address = self.ip_listbox.get(index)
        self.network_monitor.remove_ip_from_monitor(ip_address)
        self.ip_listbox.delete(index)
        self.status_var.set(f"Removed IP: {ip_address}")
        self.log_message(f"Removed IP {ip_address} from monitoring list")
    
    def toggle_monitoring(self):
        """Toggle network monitoring on/off"""
        if not self.monitoring_active.get():
            if not self.network_monitor.monitored_ips:
                messagebox.showwarning("Warning", "Please add at least one IP address to monitor")
                return
            
            self.network_monitor.start_monitoring()
            self.monitoring_active.set(True)
            self.monitor_btn.config(text="Stop Monitoring")
            self.connection_indicator.config(fg="green")
            self.status_var.set("Monitoring active")
            self.log_message("Network monitoring started")
        else:
            self.network_monitor.stop_monitoring()
            self.monitoring_active.set(False)
            self.monitor_btn.config(text="Start Monitoring")
            self.connection_indicator.config(fg="red")
            self.status_var.set("Monitoring stopped")
            self.log_message("Network monitoring stopped")
    
    def clear_data(self):
        """Clear all monitoring data"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all data?"):
            self.network_monitor.bandwidth_data.clear()
            self.network_monitor.packet_data.clear()
            
            # Clear GUI elements
            for item in self.data_tree.get_children():
                self.data_tree.delete(item)
            
            self.stats_text.delete(1.0, tk.END)
            self.status_var.set("Data cleared")
            self.log_message("All monitoring data cleared")
            
            # Update charts
            self.update_bar_chart()
            self.update_pie_chart()
    
    def export_data(self):
        """Export monitoring data to JSON file"""
        try:
            export_data = {}
            for ip in self.network_monitor.monitored_ips:
                export_data[ip] = {
                    "bandwidth_sent": list(self.network_monitor.bandwidth_data[ip]["sent"]),
                    "bandwidth_received": list(self.network_monitor.bandwidth_data[ip]["received"]),
                    "packets_sent": list(self.network_monitor.packet_data[ip]["sent"]),
                    "packets_received": list(self.network_monitor.packet_data[ip]["received"])
                }
            
            filename = f"bandwidth_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Success", f"Data exported to {filename}")
            self.status_var.set(f"Data exported to {filename}")
            self.log_message(f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")
            self.log_message(f"Error exporting data: {str(e)}")
    
    def update_bar_chart(self):
        """Update the bar chart display"""
        try:
            if self.bar_canvas:
                self.bar_canvas.get_tk_widget().destroy()
            
            fig = self.chart_manager.create_bandwidth_bar_chart(
                self.network_monitor.bandwidth_data,
                "Real-time Bandwidth Usage"
            )
            
            self.bar_canvas = FigureCanvasTkAgg(fig, self.bar_chart_frame)
            self.bar_canvas.draw()
            self.bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            self.log_message(f"Error updating bar chart: {str(e)}")
    
    def update_pie_chart(self):
        """Update the pie chart display"""
        try:
            if self.pie_canvas:
                self.pie_canvas.get_tk_widget().destroy()
            
            fig = self.chart_manager.create_bandwidth_pie_chart(
                self.network_monitor.bandwidth_data,
                "Bandwidth Distribution by IP"
            )
            
            self.pie_canvas = FigureCanvasTkAgg(fig, self.pie_chart_frame)
            self.pie_canvas.draw()
            self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            self.log_message(f"Error updating pie chart: {str(e)}")
    
    def update_statistics_display(self):
        """Update the statistics display"""
        try:
            self.stats_text.delete(1.0, tk.END)
            
            if not self.network_monitor.monitored_ips:
                self.stats_text.insert(tk.END, "No IP addresses being monitored.\n")
                self.stats_text.insert(tk.END, "Add IP addresses to start monitoring.\n")
                return
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.stats_text.insert(tk.END, f"=== BANDWIDTH MONITORING STATISTICS ===\n")
            self.stats_text.insert(tk.END, f"Last Updated: {current_time}\n")
            self.stats_text.insert(tk.END, f"Monitoring Status: {'ACTIVE' if self.monitoring_active.get() else 'INACTIVE'}\n")
            self.stats_text.insert(tk.END, f"Monitored IPs: {len(self.network_monitor.monitored_ips)}\n\n")
            
            for ip in self.network_monitor.monitored_ips:
                self.stats_text.insert(tk.END, f"📍 IP Address: {ip}\n")
                self.stats_text.insert(tk.END, f"   {'='*50}\n")
                
                # Get statistics
                total_sent, total_received = self.analyzer.get_total_bandwidth(ip)
                avg_sent, avg_received = self.analyzer.get_average_bandwidth(ip)
                peak_sent, peak_received = self.analyzer.get_peak_bandwidth(ip)
                trend_info = self.analyzer.get_bandwidth_trend(ip)
                
                self.stats_text.insert(tk.END, f"   📊 Total Data:\n")
                self.stats_text.insert(tk.END, f"      • Sent: {self.format_bytes(total_sent)}\n")
                self.stats_text.insert(tk.END, f"      • Received: {self.format_bytes(total_received)}\n")
                
                self.stats_text.insert(tk.END, f"   📈 Average Rate:\n")
                self.stats_text.insert(tk.END, f"      • Sent: {self.format_bytes(avg_sent)}/sample\n")
                self.stats_text.insert(tk.END, f"      • Received: {self.format_bytes(avg_received)}/sample\n")
                
                self.stats_text.insert(tk.END, f"   🔝 Peak Usage:\n")
                self.stats_text.insert(tk.END, f"      • Sent: {self.format_bytes(peak_sent)}\n")
                self.stats_text.insert(tk.END, f"      • Received: {self.format_bytes(peak_received)}\n")
                
                self.stats_text.insert(tk.END, f"   📊 Trend: {trend_info['trend'].upper()}\n")
                
                # Packet statistics
                packet_data = self.network_monitor.packet_data.get(ip, {"sent": deque(), "received": deque()})
                if packet_data["sent"]:
                    total_packets_sent = sum(packet_data["sent"])
                    total_packets_received = sum(packet_data["received"])
                    self.stats_text.insert(tk.END, f"   📦 Packets:\n")
                    self.stats_text.insert(tk.END, f"      • Sent: {total_packets_sent:,}\n")
                    self.stats_text.insert(tk.END, f"      • Received: {total_packets_received:,}\n")
                
                self.stats_text.insert(tk.END, f"\n")
            
            # Scroll to top
            self.stats_text.see(1.0)
            
        except Exception as e:
            self.log_message(f"Error updating statistics: {str(e)}")
    
    def update_data_table(self):
        """Update the data table with recent monitoring data"""
        try:
            # Clear existing data
            for item in self.data_tree.get_children():
                self.data_tree.delete(item)
            
            # Process data from queue
            recent_data = []
            while not self.network_monitor.data_queue.empty():
                try:
                    data = self.network_monitor.data_queue.get_nowait()
                    recent_data.append(data)
                except queue.Empty:
                    break
            
            # Add recent data to table (keep last 100 entries)
            for data in recent_data[-100:]:
                self.data_tree.insert('', 0, values=(
                    data['ip'],
                    f"{data['bytes_sent']:,}",
                    f"{data['bytes_received']:,}",
                    f"{data['packets_sent']:,}",
                    f"{data['packets_received']:,}",
                    data['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                ))
                
        except Exception as e:
            self.log_message(f"Error updating data table: {str(e)}")
    
    def format_bytes(self, bytes_value: float) -> str:
        """Format bytes into human readable format"""
        if bytes_value == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(np.floor(np.log(bytes_value) / np.log(1024)))
        p = np.power(1024, i)
        s = round(bytes_value / p, 2)
        return f"{s} {size_names[i]}"
    
    def log_message(self, message: str):
        """Add message to system logs"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.logs_text.insert(tk.END, log_entry)
        self.logs_text.see(tk.END)
        
        # Keep only last 1000 lines
        lines = self.logs_text.get(1.0, tk.END).split('\n')
        if len(lines) > 1000:
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(1.0, '\n'.join(lines[-1000:]))
    
    def load_system_logs(self):
        """Load existing system logs from file"""
        try:
            if os.path.exists('bandwidth_monitor.log'):
                with open('bandwidth_monitor.log', 'r') as f:
                    logs = f.read()
                    self.logs_text.insert(tk.END, logs)
                    self.logs_text.see(tk.END)
        except Exception as e:
            self.log_message(f"Error loading system logs: {str(e)}")
    
    def start_data_update_loop(self):
        """Start the data update loop"""
        self.update_gui_data()
        self.root.after(self.update_interval, self.start_data_update_loop)
    
    def update_gui_data(self):
        """Update all GUI data displays"""
        try:
            current_time = time.time()
            if current_time - self.last_update >= 3:  # Update every 3 seconds
                self.update_statistics_display()
                self.update_data_table()
                
                # Auto-update charts if monitoring is active
                if self.monitoring_active.get():
                    self.update_bar_chart()
                    self.update_pie_chart()
                
                self.last_update = current_time
                
        except Exception as e:
            self.log_message(f"Error in GUI update loop: {str(e)}")
    
    def run(self):
        """Start the GUI application"""
        try:
            self.log_message("CyberSec Bandwidth Monitor Pro started")
            self.status_var.set("Application ready")
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.root.mainloop()
        except Exception as e:
            logging.error(f"Error running application: {e}")
            messagebox.showerror("Critical Error", f"Application error: {str(e)}")
    
    def on_closing(self):
        """Handle application closing"""
        if self.monitoring_active.get():
            if messagebox.askokcancel("Quit", "Monitoring is active. Do you want to quit?"):
                self.network_monitor.stop_monitoring()
                self.log_message("Application closing - monitoring stopped")
                self.root.destroy()
        else:
            self.log_message("Application closing")
            self.root.destroy()

class SecurityAlertSystem:
    """Security alert system for detecting anomalies"""
    
    def __init__(self, network_monitor: NetworkMonitor):
        self.monitor = network_monitor
        self.alert_thresholds = {
            'high_bandwidth': 1024 * 1024,  # 1MB threshold
            'suspicious_packets': 1000,      # 1000 packets threshold
            'rapid_connections': 50          # 50 connections per minute
        }
        self.alerts = deque(maxlen=100)
    
    def check_for_anomalies(self):
        """Check for security anomalies in network data"""
        current_time = datetime.now()
        
        for ip in self.monitor.monitored_ips:
            bandwidth_data = self.monitor.bandwidth_data.get(ip, {"sent": deque(), "received": deque()})
            packet_data = self.monitor.packet_data.get(ip, {"sent": deque(), "received": deque()})
            
            # Check for high bandwidth usage
            if bandwidth_data["sent"] and max(bandwidth_data["sent"]) > self.alert_thresholds['high_bandwidth']:
                self.create_alert(ip, "HIGH_BANDWIDTH_OUT", 
                                f"High outbound bandwidth detected: {max(bandwidth_data['sent'])} bytes")
            
            if bandwidth_data["received"] and max(bandwidth_data["received"]) > self.alert_thresholds['high_bandwidth']:
                self.create_alert(ip, "HIGH_BANDWIDTH_IN", 
                                f"High inbound bandwidth detected: {max(bandwidth_data['received'])} bytes")
            
            # Check for suspicious packet counts
            if packet_data["sent"] and max(packet_data["sent"]) > self.alert_thresholds['suspicious_packets']:
                self.create_alert(ip, "SUSPICIOUS_PACKETS", 
                                f"High packet count detected: {max(packet_data['sent'])} packets")
    
    def create_alert(self, ip_address: str, alert_type: str, message: str):
        """Create a security alert"""
        alert = {
            'timestamp': datetime.now(),
            'ip_address': ip_address,
            'type': alert_type,
            'message': message,
            'severity': self.get_alert_severity(alert_type)
        }
        
        self.alerts.append(alert)
        logging.warning(f"SECURITY ALERT - {alert_type}: {message} for IP {ip_address}")
    
    def get_alert_severity(self, alert_type: str) -> str:
        """Get alert severity level"""
        severity_map = {
            'HIGH_BANDWIDTH_OUT': 'MEDIUM',
            'HIGH_BANDWIDTH_IN': 'MEDIUM',
            'SUSPICIOUS_PACKETS': 'HIGH',
            'RAPID_CONNECTIONS': 'HIGH'
        }
        return severity_map.get(alert_type, 'LOW')
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent alerts within specified time frame"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [alert for alert in self.alerts if alert['timestamp'] > cutoff_time]

def create_sample_configuration():
    """Create a sample configuration file"""
    config = {
        "monitoring": {
            "update_interval": 2,
            "data_retention_hours": 24,
            "auto_export": False
        },
        "alerts": {
            "high_bandwidth_threshold": 1048576,
            "packet_threshold": 1000,
            "enable_email_alerts": False,
            "email_config": {
                "smtp_server": "",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "recipient": ""
            }
        },
        "gui": {
            "theme": "purple",
            "auto_refresh": True,
            "chart_update_interval": 5
        }
    }
    
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    return config

def main():
    """Main application entry point"""
    try:
        # Create sample configuration if it doesn't exist
        if not os.path.exists('config.json'):
            create_sample_configuration()
            print("Created sample configuration file: config.json")
        
        # Initialize and run the application
        print("🛡️ Starting Accurate Cyber Defense Bandwidth Monitoring Tool...")
        print("Initializing components...")
        
        app = CyberSecurityMonitorGUI()
        
        print("✅ Application initialized successfully")
        print("🚀 Launching GUI...")
        
        app.run()
        
    except KeyboardInterrupt:
        print("\n⚠️ Application interrupted by user")
        logging.info("Application interrupted by user")
    except Exception as e:
        print(f"❌ Critical error: {str(e)}")
        logging.critical(f"Critical application error: {str(e)}")
        messagebox.showerror("Critical Error", 
                           f"A critical error occurred:\n{str(e)}\n\nCheck logs for details.")
    finally:
        print("🔒 Accurate Cyber Defense Bandwidth Monitoring Tool shutdown complete")
        logging.info("Application shutdown complete")

if __name__ == "__main__":
    # Ensure required packages are available
    required_packages = [
        'tkinter', 'matplotlib', 'numpy', 'psutil', 
        'netifaces', 'sqlite3', 'threading', 'queue'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\nInstall missing packages using:")
        print(f"pip install {' '.join(missing_packages)}")
        sys.exit(1)
    
    # Run the application
    main()