import os
import sys
import threading
import configparser
import boto3
import hashlib
import logging
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
from tkcalendar import Calendar
import customtkinter as ctk
from zoneinfo import ZoneInfo
from datetime import datetime

# Constants
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
DEFAULT_TASK_NAME = "S3BackupJob"


def get_default_python_path():
    default_dir = os.path.dirname(sys.executable)
    pythonw_path = os.path.join(default_dir, "pythonw.exe")
    return pythonw_path if os.path.exists(pythonw_path) else sys.executable


def get_default_script_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "backup_job.py")


def compute_md5(file_path):
    """Compute MD5 hash of the file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


# ---------------------------
# Backup Tab
# ---------------------------
class BackupFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.initialize_ui()
        self.load_config()

    def initialize_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)

        # Credentials
        cred_frame = ctk.CTkFrame(main_frame)
        cred_frame.grid(row=0, column=0, pady=5, padx=5, sticky="ew")
        cred_frame.grid_columnconfigure(1, weight=1)
        fields = [
            ("AWS Access Key ID:", "entry_access", False),
            ("AWS Secret Access Key:", "entry_secret", True),
            ("S3 Bucket Name:", "entry_bucket", False),
            ("Username:", "entry_computer_id", False)
        ]
        for idx, (text, attr, secret) in enumerate(fields):
            ctk.CTkLabel(cred_frame, text=text).grid(row=idx, column=0, padx=5, pady=2, sticky="w")
            entry = ctk.CTkEntry(cred_frame, show="*" if secret else "")
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            setattr(self, attr, entry)

        # Directories
        dir_frame = ctk.CTkFrame(main_frame)
        dir_frame.grid(row=1, column=0, pady=5, padx=5, sticky="ew")
        dir_frame.grid_columnconfigure(1, weight=1)

        dirs = [
            ("Local Backup Directory:", "backup_dir_entry", self.select_backup_dir),
            ("Local Restore Directory:", "restore_dir_entry", self.select_restore_dir)
        ]
        for idx, (text, attr, cmd) in enumerate(dirs):
            ctk.CTkLabel(dir_frame, text=text).grid(row=idx, column=0, padx=5, pady=2, sticky="w")
            entry = ctk.CTkEntry(dir_frame)
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            ctk.CTkButton(dir_frame, text="Browse", command=cmd).grid(row=idx, column=2, padx=5, pady=2)
            setattr(self, attr, entry)

        # Action Buttons
        btn_frame = ctk.CTkFrame(main_frame)
        btn_frame.grid(row=2, column=0, pady=10, sticky="ew")
        buttons = [
            ("Start Backup Now", self.start_backup_thread),
            ("Restore Backup", self.start_restore_thread),
            ("Save Settings", self.save_config)
        ]
        for idx, (text, cmd) in enumerate(buttons):
            btn = ctk.CTkButton(btn_frame, text=text, command=cmd)
            btn.grid(row=0, column=idx, padx=5, pady=2, sticky="ew")
            btn_frame.grid_columnconfigure(idx, weight=1)

        # Progress and Logs
        progress_frame = ctk.CTkFrame(main_frame)
        progress_frame.grid(row=3, column=0, pady=10, sticky="ew")
        self.progress_bar = ctk.CTkProgressBar(progress_frame, width=300)
        self.progress_bar.grid(row=0, column=0, padx=(5, 2))
        self.progress_bar.set(0)
        self.progress_label = ctk.CTkLabel(progress_frame, text="0%")
        self.progress_label.grid(row=0, column=1, padx=(2, 5))
        self.log_text = scrolledtext.ScrolledText(main_frame, width=100, height=12, state="disabled")
        self.log_text.grid(row=4, column=0, pady=5, sticky="nsew")

    def update_progress(self, current, total):
        progress_value = current / total if total > 0 else 0
        self.progress_bar.set(progress_value)
        percentage = int(progress_value * 100)
        self.progress_label.configure(text=f"{percentage}%")
        self.update_idletasks()

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

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


# ---------------------------
# Schedule Tab (Fixed XML)
# ---------------------------
class ScheduleFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.create_widgets()

    def create_widgets(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)

        # Time
        ctk.CTkLabel(main_frame, text="Schedule Time (HH:MM):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.hour_spin = tk.Spinbox(main_frame, from_=0, to=23, width=5, font=("Helvetica", 16))
        self.hour_spin.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.minute_spin = tk.Spinbox(main_frame, from_=0, to=59, width=5, font=("Helvetica", 16))
        self.minute_spin.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        # Frequency
        ctk.CTkLabel(main_frame, text="Schedule Frequency:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.combo_schedule = ctk.CTkComboBox(main_frame, values=["daily", "monthly", "once"])
        self.combo_schedule.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Calendar
        ctk.CTkLabel(main_frame, text="Start Date:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.calendar = Calendar(main_frame, date_pattern='mm/dd/yyyy')
        self.calendar.grid(row=2, column=1, padx=5, pady=5, sticky="w")


        # Buttons
        btn_frame = ctk.CTkFrame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ctk.CTkButton(btn_frame, text="Schedule Backup", command=self.create_task).grid(row=0, column=0, padx=5)
        ctk.CTkButton(btn_frame, text="Stop Scheduled Backup", command=self.remove_task).grid(row=0, column=1, padx=5)

        # Status
        self.status_label = ctk.CTkLabel(main_frame, text="")
        self.status_label.grid(row=5, column=0, columnspan=3, pady=10)

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
        python_cmd = f"{python_path}"
        script_arg = f"{script_path}"

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
        elif schedule == "weekly":
            day_name = start_dt.strftime("%A")  # Full weekday name
            xml += f'''    <CalendarTrigger>
      <StartBoundary>{start_boundary}</StartBoundary>
      <ScheduleByWeek>
        <WeeksInterval>1</WeeksInterval>
        <DaysOfWeek>
          <Day>{day_name}</Day>
        </DaysOfWeek>
      </ScheduleByWeek>
      <Enabled>true</Enabled>
    </CalendarTrigger>'''
        elif schedule == "monthly":
            day_of_month = start_dt.day
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
                self.status_label.configure(text="Schedule created successfully!", text_color="green")
            else:
                self.status_label.configure(text="Failed to create schedule", text_color="red")

            os.remove(temp_xml_path)
        except Exception as e:
            self.status_label.configure(text=f"Error: {str(e)}", text_color="red")

    def remove_task(self):
        command = f'schtasks /delete /tn "{DEFAULT_TASK_NAME}" /f'
        result = os.system(command)
        if result == 0:
            self.status_label.configure(text="Scheduled task removed", text_color="green")
        else:
            self.status_label.configure(text="Failed to remove task", text_color="red")


# ---------------------------
# Browse & Restore Tab
# ---------------------------
class BrowseRestoreFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.create_widgets()
        self.load_config()

    def create_widgets(self):
        cred_frame = ctk.CTkFrame(self)
        cred_frame.pack(fill="x", padx=10, pady=5)
        fields = [
            ("AWS Access Key ID:", "entry_access", False),
            ("AWS Secret Access Key:", "entry_secret", True),
            ("S3 Bucket Name:", "entry_bucket", False),
            ("Username:", "entry_computer_id", False)
        ]
        for idx, (label_text, attr, secret) in enumerate(fields):
            ctk.CTkLabel(cred_frame, text=label_text).grid(row=idx, column=0, padx=5, pady=2, sticky="w")
            entry = ctk.CTkEntry(cred_frame, show="*" if secret else "")
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            setattr(self, attr, entry)
        cred_frame.grid_columnconfigure(1, weight=1)

        refresh_btn = ctk.CTkButton(self, text="Refresh File List", command=self.refresh_file_list)
        refresh_btn.pack(padx=10, pady=5)

        tree_frame = ctk.CTkFrame(self)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background="white",
                        foreground="black",
                        fieldbackground="white",
                        rowheight=25,
                        font=("Helvetica", 10))
        style.configure("Treeview.Heading", font=("Helvetica", 11, "bold"))
        style.map("Treeview", background=[("selected", "#347083")])

        self.tree = ttk.Treeview(tree_frame,
                                 columns=("Name", "Size", "Last Modified", "S3 Key"),
                                 show="headings",
                                 selectmode="extended")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Size", text="Size (bytes)")
        self.tree.heading("Last Modified", text="Last Modified")
        self.tree.heading("S3 Key", text="S3 Key")
        self.tree.column("Name", width=200, anchor="w")
        self.tree.column("Size", width=100, anchor="center")
        self.tree.column("Last Modified", width=150, anchor="center")
        self.tree.column("S3 Key", width=300, anchor="w")
        self.tree.pack(fill="both", expand=True)

        restore_frame = ctk.CTkFrame(self)
        restore_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(restore_frame, text="Restore Directory:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.restore_dir_entry = ctk.CTkEntry(restore_frame)
        self.restore_dir_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        restore_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(restore_frame, text="Browse", command=self.select_restore_dir).grid(row=0, column=2, padx=5,
                                                                                          pady=2)

        restore_btn = ctk.CTkButton(self, text="Restore Selected Files", command=self.restore_selected_files)
        restore_btn.pack(padx=10, pady=5)

        progress_frame = ctk.CTkFrame(self)
        progress_frame.pack(fill="x", padx=10, pady=5)
        self.progress_bar = ctk.CTkProgressBar(progress_frame, width=300)
        self.progress_bar.grid(row=0, column=0, padx=(5, 2))
        self.progress_bar.set(0)
        self.progress_label = ctk.CTkLabel(progress_frame, text="0%")
        self.progress_label.grid(row=0, column=1, padx=(2, 5))
        self.log_text = scrolledtext.ScrolledText(self, height=10, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)

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
                self.restore_dir_entry.insert(0, settings.get("restore_dir", ""))
                self.log("Loaded configuration from file.")

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

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

    def refresh_file_list(self):
        s3 = self.get_s3_client()
        if s3 is None:
            return
        bucket = self.entry_bucket.get().strip()
        computer_folder = self.entry_computer_id.get().strip() or "Default"
        prefix = f"backup/{computer_folder}/"
        try:
            paginator = s3.get_paginator('list_objects_v2')
            self.tree.delete(*self.tree.get_children())
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        key = obj['Key']
                        size = obj['Size']
                        last_modified = obj.get('LastModified')
                        if last_modified:
                            local_time = last_modified.astimezone(ZoneInfo("America/Toronto"))
                            last_modified = local_time.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            last_modified = "N/A"
                        name = os.path.basename(key)
                        self.tree.insert("", "end", values=(name, size, last_modified, key))
            self.log("File list refreshed.")
        except Exception as e:
            self.log(f"Error refreshing file list: {e}")

    def update_progress(self, current, total):
        progress_value = current / total if total > 0 else 0
        self.progress_bar.set(progress_value)
        percentage = int(progress_value * 100)
        self.progress_label.configure(text=f"{percentage}%")
        self.update_idletasks()

    def restore_selected_files(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "No files selected for restore.")
            return

        restore_dir = self.restore_dir_entry.get().strip()
        if not restore_dir:
            messagebox.showerror("Error", "Please select a restore directory.")
            return

        s3 = self.get_s3_client()
        if s3 is None:
            return

        bucket = self.entry_bucket.get().strip()
        total_size = 0
        files_to_restore = []
        for item in selected_items:
            name, size, last_modified, s3_key = self.tree.item(item, "values")
            size = int(size)
            total_size += size
            files_to_restore.append((s3_key, size))

        self.bytes_downloaded = 0
        self.progress_bar.set(0)
        self.progress_label.configure(text="0%")

        def download_progress_callback(bytes_amount):
            self.bytes_downloaded += bytes_amount
            self.update_progress(self.bytes_downloaded, total_size)

        def restore_thread():
            for s3_key, size in files_to_restore:
                rel_path = os.path.relpath(s3_key, f"backup/{self.entry_computer_id.get().strip() or 'Default'}")
                local_path = os.path.join(restore_dir, rel_path)
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                try:
                    s3.download_file(bucket, s3_key, local_path, Callback=download_progress_callback)
                    self.log(f"Restored {s3_key} to {local_path}")
                except Exception as e:
                    self.log(f"Error restoring {s3_key}: {e}")
            messagebox.showinfo("Restore", "Selected files have been restored.")

        threading.Thread(target=restore_thread, daemon=True).start()


# ---------------------------
# Main Application
# ---------------------------
class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("S3Sync")
        self.geometry("900x750")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(expand=True, fill="both", padx=10, pady=10)

        self.tab_view.add("Backup")
        self.backup_tab = BackupFrame(self.tab_view.tab("Backup"))
        self.backup_tab.pack(expand=True, fill="both")

        self.tab_view.add("Schedule")
        self.schedule_tab = ScheduleFrame(self.tab_view.tab("Schedule"))
        self.schedule_tab.pack(expand=True, fill="both")

        self.tab_view.add("Browse & Restore")
        self.browse_restore_tab = BrowseRestoreFrame(self.tab_view.tab("Browse & Restore"))
        self.browse_restore_tab.pack(expand=True, fill="both")


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
