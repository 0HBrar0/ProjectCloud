import os
import sys
import threading
import configparser
import boto3
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkcalendar import Calendar
import customtkinter as ctk
from zoneinfo import ZoneInfo
from datetime import datetime
import darkdetect

# Configure appearance
ctk.set_appearance_mode("dark" if darkdetect.isDark() else "light")
ctk.set_default_color_theme("blue")

# Constants
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
DEFAULT_TASK_NAME = "S3BackupJob"

# Style Configuration
ACCENT_COLOR = "#2A9FD6"
TITLE_FONT = ("Helvetica", 16, "bold")
LABEL_FONT = ("Helvetica", 12)
BUTTON_FONT = ("Helvetica", 12, "bold")
ENTRY_FONT = ("Helvetica", 12)
LOG_FONT = ("Consolas", 10)

def get_default_python_path():
    default_dir = os.path.dirname(sys.executable)
    pythonw_path = os.path.join(default_dir, "pythonw.exe")
    return pythonw_path if os.path.exists(pythonw_path) else sys.executable

def get_default_script_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "backup_job.py")

def compute_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

class BackupFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.initialize_ui()
        self.load_config()

    def initialize_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)

        # Header
        header = ctk.CTkLabel(main_frame, text="Cloud Backup Manager", font=TITLE_FONT)
        header.grid(row=0, column=0, pady=(0, 15), sticky="w")

        # Credentials Frame
        cred_frame = ctk.CTkFrame(main_frame, border_width=1)
        cred_frame.grid(row=1, column=0, pady=5, padx=5, sticky="ew")
        ctk.CTkLabel(cred_frame, text="AWS Credentials", font=LABEL_FONT).grid(row=0, column=0, sticky="w", pady=5)

        fields = [
            ("Access Key ID:", "entry_access", False),
            ("Secret Key:", "entry_secret", True),
            ("Bucket Name:", "entry_bucket", False),
            ("User Directory:", "entry_computer_id", False)
        ]
        for idx, (text, attr, secret) in enumerate(fields, start=1):
            ctk.CTkLabel(cred_frame, text=text).grid(row=idx, column=0, padx=5, pady=2, sticky="w")
            entry = ctk.CTkEntry(cred_frame, show="*" if secret else "", font=ENTRY_FONT)
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            setattr(self, attr, entry)
            cred_frame.grid_columnconfigure(1, weight=1)

        # Directory Frame
        dir_frame = ctk.CTkFrame(main_frame, border_width=1)
        dir_frame.grid(row=2, column=0, pady=5, padx=5, sticky="ew")
        ctk.CTkLabel(dir_frame, text="Directory Configuration", font=LABEL_FONT).grid(row=0, column=0, sticky="w", pady=5)

        dirs = [
            ("Backup Directory:", "backup_dir_entry", self.select_backup_dir),
            ("Restore Directory:", "restore_dir_entry", self.select_restore_dir)
        ]
        for idx, (text, attr, cmd) in enumerate(dirs, start=1):
            ctk.CTkLabel(dir_frame, text=text).grid(row=idx, column=0, padx=5, pady=2, sticky="w")
            entry = ctk.CTkEntry(dir_frame, font=ENTRY_FONT)
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            btn = ctk.CTkButton(dir_frame, text="Browse", command=cmd, width=80, font=BUTTON_FONT)
            btn.grid(row=idx, column=2, padx=5, pady=2)
            setattr(self, attr, entry)
            dir_frame.grid_columnconfigure(1, weight=1)

        # Action Buttons
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.grid(row=3, column=0, pady=10, sticky="ew")
        buttons = [
            ("Start Backup Now", self.start_backup_thread, "#28a745"),
            ("Restore Backup", self.start_restore_thread, "#17a2b8"),
            ("Save Settings", self.save_config, "#6c757d")
        ]
        for idx, (text, cmd, color) in enumerate(buttons):
            btn = ctk.CTkButton(btn_frame, text=text, command=cmd, font=BUTTON_FONT, fg_color=color)
            btn.grid(row=0, column=idx, padx=5, pady=2, sticky="ew")
            btn_frame.grid_columnconfigure(idx, weight=1)

        # Progress and Logs
        progress_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        progress_frame.grid(row=4, column=0, pady=10, sticky="ew")
        progress_frame.grid_columnconfigure(0, weight=1)  # Allow column to expand

        self.progress_bar = ctk.CTkProgressBar(progress_frame, width=300, progress_color=ACCENT_COLOR)
        self.progress_bar.grid(row=0, column=0, padx=(5, 2), sticky="ew")  # Remove width, add sticky
        self.progress_bar.set(0)
        self.progress_label = ctk.CTkLabel(progress_frame, text="0%", font=LABEL_FONT)
        self.progress_label.grid(row=1, column=0, pady=(5, 0))

        self.log_text = ctk.CTkTextbox(main_frame, width=100, height=150, font=LOG_FONT)
        self.log_text.grid(row=5, column=0, pady=5, sticky="nsew")

    def update_progress(self, current, total):
        progress_value = current / total if total > 0 else 0
        self.progress_bar.set(progress_value)
        percentage = int(progress_value * 100)
        self.progress_label.configure(text=f"{percentage}%")
        self.update_idletasks()

    def log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def select_backup_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.backup_dir_entry.delete(0, "end")
            self.backup_dir_entry.insert(0, directory)
            self.log(f"Selected backup directory: {directory}")

    def select_restore_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.restore_dir_entry.delete(0, "end")
            self.restore_dir_entry.insert(0, directory)
            self.log(f"Selected restore directory: {directory}")

    def get_s3_client(self):
        access_key = self.entry_access.get().strip()
        secret_key = self.entry_secret.get().strip()
        if not access_key or not secret_key:
            messagebox.showerror("Error", "Please provide AWS credentials.")
            return None
        return boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)

    def backup_directory(self):
        local_dir = self.backup_dir_entry.get()
        bucket = self.entry_bucket.get().strip()
        computer_folder = self.entry_computer_id.get().strip() or "Default"
        prefix = f"backup/{computer_folder}/"

        if not local_dir or not bucket:
            messagebox.showerror("Error", "Please select a backup directory and enter a bucket name.")
            return

        s3 = self.get_s3_client()
        if s3 is None:
            return

        total_size = 0
        file_list = []
        for root, _, files in os.walk(local_dir):
            for file in files:
                full_path = os.path.join(root, file)
                total_size += os.path.getsize(full_path)
                rel_path = os.path.relpath(full_path, local_dir)
                file_list.append((full_path, rel_path))

        self.total_size = total_size
        self.bytes_uploaded = 0
        self.progress_bar.set(0)
        self.progress_label.configure(text="0%")

        def progress_callback(bytes_amount):
            self.bytes_uploaded += bytes_amount
            self.update_progress(self.bytes_uploaded, self.total_size)

        for full_path, rel_path in file_list:
            s3_key = os.path.join(prefix, rel_path).replace("\\", "/")
            local_md5 = compute_md5(full_path)

            try:
                response = s3.head_object(Bucket=bucket, Key=s3_key)
                s3_md5 = response['Metadata'].get('file_md5', None)
                if s3_md5 == local_md5:
                    self.log(f"Skipping {full_path} (no changes)")
                    self.bytes_uploaded += os.path.getsize(full_path)
                    self.update_progress(self.bytes_uploaded, self.total_size)
                    continue
            except Exception:
                pass

            try:
                s3.upload_file(
                    full_path,
                    bucket,
                    s3_key,
                    ExtraArgs={'Metadata': {'file_md5': local_md5}},
                    Callback=progress_callback
                )
                self.log(f"Uploaded {full_path} to s3://{bucket}/{s3_key}")
            except Exception as e:
                self.log(f"Error uploading {full_path}: {e}")

    def restore_backup(self):
        bucket = self.entry_bucket.get().strip()
        restore_dir = self.restore_dir_entry.get()
        computer_folder = self.entry_computer_id.get().strip() or "Default"
        prefix = f"backup/{computer_folder}/"

        if not bucket or not restore_dir:
            messagebox.showerror("Error", "Please enter bucket name and select restore directory.")
            return

        s3 = self.get_s3_client()
        if s3 is None:
            return

        paginator = s3.get_paginator('list_objects_v2')
        total_download_size = 0
        object_list = []

        try:
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        total_download_size += obj['Size']
                        object_list.append((obj['Key'], obj['Size']))
        except Exception as e:
            self.log(f"Error listing objects: {e}")
            return

        self.total_download_size = total_download_size
        self.bytes_downloaded = 0
        self.progress_bar.set(0)
        self.progress_label.configure(text="0%")

        def download_progress_callback(bytes_amount):
            self.bytes_downloaded += bytes_amount
            self.update_progress(self.bytes_downloaded, self.total_download_size)

        for s3_key, size in object_list:
            rel_path = os.path.relpath(s3_key, prefix)
            local_path = os.path.join(restore_dir, rel_path)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            try:
                s3.download_file(
                    bucket,
                    s3_key,
                    local_path,
                    Callback=download_progress_callback
                )
                self.log(f"Downloaded {s3_key} to {local_path}")
            except Exception as e:
                self.log(f"Error downloading {s3_key}: {e}")

    def start_backup_thread(self):
        threading.Thread(target=self.run_backup, daemon=True).start()

    def run_backup(self):
        try:
            self.log("Starting backup...")
            self.backup_directory()
            self.log("Backup completed successfully!")
            messagebox.showinfo("Backup", "Backup completed successfully!")
        except Exception as e:
            self.log(f"Backup error: {e}")
            messagebox.showerror("Backup Error", str(e))

    def start_restore_thread(self):
        threading.Thread(target=self.run_restore, daemon=True).start()

    def run_restore(self):
        try:
            self.log("Starting restore...")
            self.restore_backup()
            self.log("Restore completed successfully!")
            messagebox.showinfo("Restore", "Restore completed successfully!")
        except Exception as e:
            self.log(f"Restore error: {e}")
            messagebox.showerror("Restore Error", str(e))

    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
            if "Settings" in config:
                settings = config["Settings"]
                self.entry_access.insert(0, settings.get("aws_access_key", ""))
                self.entry_secret.insert(0, settings.get("aws_secret_key", ""))
                self.entry_bucket.insert(0, settings.get("bucket_name", ""))
                self.entry_computer_id.insert(0, settings.get("computer_id", ""))
                self.backup_dir_entry.insert(0, settings.get("backup_dir", ""))
                self.restore_dir_entry.insert(0, settings.get("restore_dir", ""))
                self.log("Loaded configuration from file.")

    def save_config(self):
        config = configparser.ConfigParser()
        config["Settings"] = {
            "aws_access_key": self.entry_access.get(),
            "aws_secret_key": self.entry_secret.get(),
            "bucket_name": self.entry_bucket.get(),
            "computer_id": self.entry_computer_id.get(),
            "backup_dir": self.backup_dir_entry.get(),
            "restore_dir": self.restore_dir_entry.get()
        }
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        self.log("Configuration saved")
        messagebox.showinfo("Success", "Settings saved successfully")

class ScheduleFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.create_widgets()
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.configure_tree_style()

    def configure_tree_style(self):
        self.style.configure("Calendar",
                             background="#2B2B2B" if darkdetect.isDark() else "white",
                             foreground="white" if darkdetect.isDark() else "black",
                             headersbackground="#333333",
                             selectbackground=ACCENT_COLOR)
        self.style.map("Calendar",
                       background=[("selected", ACCENT_COLOR)],
                       foreground=[("selected", "white")])

    def create_widgets(self):
        header = ctk.CTkLabel(self, text="Backup Scheduler", font=TITLE_FONT)
        header.pack(pady=(10, 20), anchor="w", padx=20)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20)

        # Time Selection
        time_frame = ctk.CTkFrame(content, border_width=1)
        time_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(time_frame, text="Schedule Time", font=LABEL_FONT).pack(pady=5, anchor="w", padx=5)

        spin_frame = ctk.CTkFrame(time_frame, fg_color="transparent")
        spin_frame.pack(pady=5)
        self.hour_spin = tk.Spinbox(spin_frame, from_=0, to=23, width=3,
                                    font=("Helvetica", 25), bg="#2B2B2B", fg="white")
        self.hour_spin.pack(side="left", padx=5)
        ctk.CTkLabel(spin_frame, text=":").pack(side="left")
        self.minute_spin = tk.Spinbox(spin_frame, from_=0, to=59, width=3,
                                      font=("Helvetica", 25), bg="#2B2B2B", fg="white")
        self.minute_spin.pack(side="left", padx=5)

        # Frequency Selection
        freq_frame = ctk.CTkFrame(content, border_width=1)
        freq_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(freq_frame, text="Schedule Frequency", font=LABEL_FONT).pack(pady=5, anchor="w", padx=5)
        self.combo_schedule = ctk.CTkComboBox(freq_frame,
                                              values=["daily", "monthly", "once"],
                                              button_color=ACCENT_COLOR)
        self.combo_schedule.pack(pady=5, fill="x", padx=5)

        # Calendar
        cal_frame = ctk.CTkFrame(content, border_width=1)
        cal_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(cal_frame, text="Start Date", font=LABEL_FONT).pack(pady=5, anchor="w", padx=5)
        self.calendar = Calendar(cal_frame,
                                 date_pattern='mm/dd/yyyy',
                                 font="Helvetica 12",
                                 background="#2B2B2B",
                                 foreground="white",
                                 bordercolor=ACCENT_COLOR,
                                 headersbackground="#333333",
                                 normalbackground="#2B2B2B",
                                 weekendbackground="#3B3B3B",
                                 selectbackground=ACCENT_COLOR)
        self.calendar.pack(pady=5, padx=5)

        # Action Buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=20)
        ctk.CTkButton(btn_frame,
                      text="Schedule Backup",
                      command=self.create_task,
                      fg_color=ACCENT_COLOR,
                      font=BUTTON_FONT).grid(row=0, column=0, padx=5)
        ctk.CTkButton(btn_frame,
                      text="Remove Schedule",
                      command=self.remove_task,
                      fg_color="#dc3545",
                      font=BUTTON_FONT).grid(row=0, column=1, padx=5)

        self.status_label = ctk.CTkLabel(content, text="", font=LABEL_FONT)
        self.status_label.pack(pady=10)

    def create_task(self):
        schedule = self.combo_schedule.get().strip()
        start_date = self.calendar.get_date()
        selected_time = f"{self.hour_spin.get()}:{self.minute_spin.get()}"

        if not schedule or not selected_time:
            self.status_label.configure(text="Missing required fields!", text_color="red")
            return

        try:
            start_dt = datetime.strptime(f"{start_date} {selected_time}", "%m/%d/%Y %H:%M")
        except Exception:
            self.status_label.configure(text="Invalid date/time format", text_color="red")
            return

        start_boundary = start_dt.isoformat()
        python_path = get_default_python_path()
        script_path = get_default_script_path()
        python_cmd = f'"{python_path}"'
        script_arg = f'"{script_path}"'

        xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{datetime.now().isoformat()}</Date>
    <Author>{os.getlogin()}</Author>
    <Description>S3 Backup Job</Description>
  </RegistrationInfo>
  <Triggers>'''

        if schedule == "once":
            xml += f'''    <TimeTrigger>
      <StartBoundary>{start_boundary}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>'''
        elif schedule == "daily":
            xml += f'''    <CalendarTrigger>
      <StartBoundary>{start_boundary}</StartBoundary>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
      <Enabled>true</Enabled>
    </CalendarTrigger>'''
        elif schedule == "monthly":
            day_of_month = start_dt.day
            # Fixed: Use numeric months (1-12)
            months = ["January", "February", "March", "April", "May", "June",
                      "July", "August", "September", "October", "November", "December"]
            months_xml = "".join([f"<{m}/>\n          " for m in months])  # Self-closing tags
            xml += f'''    <CalendarTrigger>
      <StartBoundary>{start_boundary}</StartBoundary>
      <ScheduleByMonth>
        <DaysOfMonth>
          <Day>{day_of_month}</Day>
        </DaysOfMonth>
        <Months>
          {months_xml}
        </Months>
      </ScheduleByMonth>
      <Enabled>true</Enabled>
    </CalendarTrigger>'''
        else:
            self.status_label.configure(text="Unrecognized schedule.", text_color="red")
            return

        xml += f'''  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{python_cmd}</Command>
      <Arguments>{script_arg}</Arguments>
    </Exec>
  </Actions>
</Task>'''

        temp_xml_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_task.xml")
        try:
            with open(temp_xml_path, "w", encoding="utf-16") as f:
                f.write(xml)

            command = f'schtasks /create /tn "{DEFAULT_TASK_NAME}" /xml "{temp_xml_path}" /f'
            result = os.system(command)

            if result == 0:
                self.status_label.configure(text="Schedule created successfully!", text_color=ACCENT_COLOR)
            else:
                self.status_label.configure(text="Failed to create schedule", text_color="red")

            os.remove(temp_xml_path)
        except Exception as e:
            self.status_label.configure(text=f"Error: {str(e)}", text_color="red")

    def remove_task(self):
        command = f'schtasks /delete /tn "{DEFAULT_TASK_NAME}" /f'
        result = os.system(command)
        if result == 0:
            self.status_label.configure(text="Scheduled task removed", text_color=ACCENT_COLOR)
        else:
            self.status_label.configure(text="Failed to remove task", text_color="red")

class BrowseRestoreFrame(ctk.CTkFrame):
    def __init__(self, master, backup_tab, **kwargs):
        super().__init__(master, **kwargs)
        self.backup_tab = backup_tab
        self.create_widgets()
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.configure_tree_style()
        self.load_config()
        self.running = False

    def configure_tree_style(self):
        self.style.configure("Treeview",
                             background="#2B2B2B" if darkdetect.isDark() else "white",
                             foreground="white" if darkdetect.isDark() else "black",
                             fieldbackground="#2B2B2B",
                             rowheight=30,
                             font=("Helvetica", 11))
        self.style.configure("Treeview.Heading",
                             font=("Helvetica", 12, "bold"),
                             background=ACCENT_COLOR,
                             foreground="white")
        self.style.map("Treeview", background=[("selected", ACCENT_COLOR)])

    def create_widgets(self):
        header = ctk.CTkLabel(self, text="Cloud Restore Browser", font=TITLE_FONT)
        header.pack(pady=(10, 20), anchor="w", padx=20)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20)

        # Treeview
        tree_frame = ctk.CTkFrame(content)
        tree_frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(tree_frame,
                                 columns=("Name", "Size", "Last Modified", "S3 Key"),
                                 show="headings",
                                 selectmode="extended")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        # Configure columns
        columns = [
            ("Name", 200),
            ("Size", 100),
            ("Last Modified", 150),
            ("S3 Key", 300)
        ]
        for col, width in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")

        # Restore Controls
        restore_controls = ctk.CTkFrame(content, fg_color="transparent")
        restore_controls.pack(fill="x", pady=10)

        ctk.CTkButton(restore_controls,
                      text="Refresh",
                      command=self.refresh_file_list,
                      fg_color=ACCENT_COLOR).pack(side="left", padx=5)

        dir_frame = ctk.CTkFrame(restore_controls, fg_color="transparent")
        dir_frame.pack(side="left", expand=True, fill="x", padx=10)
        ctk.CTkLabel(dir_frame, text="Restore Directory:").pack(side="left")
        self.restore_dir_entry = ctk.CTkEntry(dir_frame)
        self.restore_dir_entry.pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkButton(dir_frame,
                      text="Browse",
                      command=self.select_restore_dir,
                      fg_color=ACCENT_COLOR).pack(side="left")

        self.restore_btn = ctk.CTkButton(restore_controls,
                                       text="Restore Selected",
                                       command=self.start_restore_thread,
                                       fg_color="#28a745")
        self.restore_btn.pack(side="right", padx=5)

        # Progress
        self.progress_bar = ctk.CTkProgressBar(content, progress_color=ACCENT_COLOR)
        self.progress_bar.pack(fill="x", pady=10)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(content, text="0%", font=LABEL_FONT)
        self.progress_label.pack()

        # Logs
        self.log_text = ctk.CTkTextbox(content, height=150, font=LOG_FONT)
        self.log_text.pack(fill="both", expand=True, pady=10)

    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
            if "Settings" in config:
                settings = config["Settings"]
                self.restore_dir_entry.insert(0, settings.get("restore_dir", ""))

    def refresh_file_list(self):
        try:
            s3 = self.get_s3_client()
            if s3 is None:
                return

            bucket = self.backup_tab.entry_bucket.get().strip()
            computer_folder = self.backup_tab.entry_computer_id.get().strip() or "Default"
            prefix = f"backup/{computer_folder}/"

            self.tree.delete(*self.tree.get_children())
            paginator = s3.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        key = obj['Key']
                        size = obj['Size']
                        last_modified = obj['LastModified'].astimezone(ZoneInfo("America/Toronto"))
                        self.tree.insert("", "end", values=(
                            os.path.basename(key),
                            size,
                            last_modified.strftime("%Y-%m-%d %H:%M:%S"),
                            key
                        ))
            self.log("File list refreshed successfully")
        except Exception as e:
            self.log(f"Error refreshing file list: {str(e)}")
            messagebox.showerror("Error", f"Failed to refresh files: {str(e)}")

    def start_restore_thread(self):
        if not self.running:
            self.running = True
            self.restore_btn.configure(text="Restoring...", fg_color="#dc3545")
            threading.Thread(target=self.restore_selected_files, daemon=True).start()
        else:
            self.running = False
            self.restore_btn.configure(text="Restore Selected", fg_color="#28a745")

    def restore_selected_files(self):
        try:
            selected_items = self.tree.selection()
            if not selected_items:
                messagebox.showwarning("Warning", "No files selected for restore")
                return

            restore_dir = self.restore_dir_entry.get().strip()
            if not restore_dir:
                messagebox.showerror("Error", "Please select a restore directory")
                return

            s3 = self.get_s3_client()
            if s3 is None:
                return

            bucket = self.backup_tab.entry_bucket.get().strip()
            total_size = sum(int(self.tree.item(item)['values'][1]) for item in selected_items)
            self.bytes_downloaded = 0
            self.progress_bar.set(0)
            self.progress_label.configure(text="0%")

            def download_progress_callback(bytes_amount):
                self.bytes_downloaded += bytes_amount
                self.after(10, self.update_progress, self.bytes_downloaded, total_size)

            for item in selected_items:
                if not self.running:
                    break
                s3_key = self.tree.item(item)['values'][3]
                local_path = os.path.join(restore_dir, os.path.relpath(s3_key,
                                                                       f"backup/{self.backup_tab.entry_computer_id.get().strip() or 'Default'}"))
                os.makedirs(os.path.dirname(local_path), exist_ok=True)

                try:
                    s3.download_file(bucket, s3_key, local_path, Callback=download_progress_callback)
                    self.log(f"Successfully restored: {os.path.basename(local_path)}")
                except Exception as e:
                    self.log(f"Failed to restore {s3_key}: {str(e)}")

            if self.running:
                messagebox.showinfo("Restore Complete", "Selected files restoration completed")
            self.running = False
            self.restore_btn.configure(text="Restore Selected", fg_color="#28a745")

        except Exception as e:
            self.log(f"Restore error: {str(e)}")
            messagebox.showerror("Error", f"Restore failed: {str(e)}")
        finally:
            self.running = False
            self.restore_btn.configure(text="Restore Selected", fg_color="#28a745")

    def select_restore_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.restore_dir_entry.delete(0, "end")
            self.restore_dir_entry.insert(0, directory)
            self.log(f"Restore directory set to: {directory}")

    def update_progress(self, current, total):
        progress = current / total if total > 0 else 0
        self.progress_bar.set(progress)
        self.progress_label.configure(text=f"{int(progress * 100)}%")

    def log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def get_s3_client(self):
        access_key = self.backup_tab.entry_access.get().strip()
        secret_key = self.backup_tab.entry_secret.get().strip()
        if not access_key or not secret_key:
            messagebox.showerror("Error", "AWS credentials required")
            return None
        return boto3.client('s3',
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key)

class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("S3Sync")
        self.geometry("1100x800")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(expand=True, fill="both", padx=10, pady=10)

        # Create backup tab first
        self.tab_view.add("Backup")
        self.backup_tab = BackupFrame(self.tab_view.tab("Backup"))
        self.backup_tab.pack(expand=True, fill="both")

        # Create other tabs with reference to backup tab
        self.tab_view.add("Schedule")
        self.schedule_tab = ScheduleFrame(self.tab_view.tab("Schedule"))
        self.schedule_tab.pack(expand=True, fill="both")

        self.tab_view.add("Browse & Restore")
        self.browse_restore_tab = BrowseRestoreFrame(
            self.tab_view.tab("Browse & Restore"),
            self.backup_tab
        )
        self.browse_restore_tab.pack(expand=True, fill="both")

if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
