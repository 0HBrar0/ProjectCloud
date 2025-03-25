import os
import threading
import configparser
import boto3
import hashlib
from botocore.exceptions import NoCredentialsError, ClientError
import customtkinter as ctk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk

CONFIG_FILE = "config.ini"
TIME_CONVERSIONS = {
    "Seconds": 1000,
    "Minutes": 60000,
    "Hours": 3600000,
    "Days": 86400000
}


class S3BackupApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("S3Sync Pro")
        self.geometry("850x750")
        self.resizable(True, True)
        self.scheduled_job = None

        # Initialize all UI elements
        self.entry_access = None
        self.entry_secret = None
        self.entry_bucket = None
        self.entry_computer_id = None
        self.backup_dir_entry = None
        self.restore_dir_entry = None
        self.entry_interval = None
        self.interval_unit = None

        self.setup_ui()
        self.load_config()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Main frame
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)

        # Credential Fields
        cred_frame = ctk.CTkFrame(main_frame)
        cred_frame.grid(row=0, column=0, pady=5, padx=5, sticky="ew")

        fields = [
            ("AWS Access Key ID:", "entry_access", False),
            ("AWS Secret Access Key:", "entry_secret", True),
            ("S3 Bucket Name:", "entry_bucket", False),
            ("Username:", "entry_computer_id", False)
        ]

        for idx, (label_text, attr_name, is_secret) in enumerate(fields):
            ctk.CTkLabel(cred_frame, text=label_text).grid(row=idx, column=0, padx=5, pady=2, sticky="w")
            entry = ctk.CTkEntry(cred_frame, show="*" if is_secret else "", width=300)
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            setattr(self, attr_name, entry)

        # Directory Selection
        dir_frame = ctk.CTkFrame(main_frame)
        dir_frame.grid(row=1, column=0, pady=5, padx=5, sticky="ew")

        dirs = [
            ("Local Backup Directory:", "backup_dir_entry", self.select_backup_directory),
            ("Local Restore Directory:", "restore_dir_entry", self.select_restore_directory)
        ]

        for idx, (label_text, attr_name, command) in enumerate(dirs):
            ctk.CTkLabel(dir_frame, text=label_text).grid(row=idx, column=0, padx=5, pady=2, sticky="w")
            entry = ctk.CTkEntry(dir_frame, width=300)
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            btn = ctk.CTkButton(dir_frame, text="Browse", command=command)
            btn.grid(row=idx, column=2, padx=5, pady=2)
            setattr(self, attr_name, entry)

        # Settings
        settings_frame = ctk.CTkFrame(main_frame)
        settings_frame.grid(row=2, column=0, pady=5, padx=5, sticky="ew")

        # Backup Interval
        ctk.CTkLabel(settings_frame, text="Backup Interval:").grid(row=0, column=0, padx=5)
        self.entry_interval = ctk.CTkEntry(settings_frame, width=70)
        self.entry_interval.grid(row=0, column=1, padx=5)
        self.entry_interval.insert(0, "60")
        self.interval_unit = ctk.CTkOptionMenu(settings_frame, values=list(TIME_CONVERSIONS.keys()))
        self.interval_unit.grid(row=0, column=2, padx=5)

        # Action Buttons
        btn_frame = ctk.CTkFrame(main_frame)
        btn_frame.grid(row=3, column=0, pady=10, sticky="ew")

        buttons = [
            ("Start Backup Now", self.start_backup_thread),
            ("Restore Backup", self.start_restore_thread),
            ("Start Schedule", self.start_scheduled_backup),
            ("Stop Schedule", self.stop_scheduled_backup),
            ("Save Settings", self.save_config)
        ]

        for idx, (text, command) in enumerate(buttons):
            btn = ctk.CTkButton(btn_frame, text=text, command=command)
            btn.grid(row=0, column=idx, padx=5, pady=2)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(main_frame, width=300)
        self.progress_bar.grid(row=4, column=0, pady=5)
        self.progress_bar.set(0)

        # Log Output
        self.log_text = scrolledtext.ScrolledText(main_frame, width=100, height=15, state="disabled")
        self.log_text.grid(row=5, column=0, pady=5, sticky="nsew")

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def select_backup_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.backup_dir_entry.delete(0, "end")
            self.backup_dir_entry.insert(0, directory)
            self.log(f"Selected backup directory: {directory}")

    def select_restore_directory(self):
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
        return boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )

    def compute_md5(self, file_path):
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

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

        # Gather files and calculate total size
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

        def progress_callback(bytes_amount):
            self.bytes_uploaded += bytes_amount
            progress_value = self.bytes_uploaded / self.total_size if self.total_size > 0 else 0
            self.progress_bar.set(progress_value)
            self.update_idletasks()

        for full_path, rel_path in file_list:
            s3_key = os.path.join(prefix, rel_path).replace("\\", "/")
            local_md5 = self.compute_md5(full_path)

            try:
                # Check existing file
                response = s3.head_object(Bucket=bucket, Key=s3_key)
                s3_md5 = response['Metadata'].get('file_md5', None)

                if s3_md5 == local_md5:
                    self.log(f"Skipping {full_path} (no changes)")
                    self.bytes_uploaded += os.path.getsize(full_path)
                    progress_callback(0)
                    continue

            except ClientError as e:
                if e.response['Error']['Code'] != '404':
                    self.log(f"Error checking {s3_key}: {e}")
                    continue

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
        except ClientError as e:
            self.log(f"Error listing objects: {e}")
            return

        self.total_download_size = total_download_size
        self.bytes_downloaded = 0
        self.progress_bar.set(0)

        def download_progress_callback(bytes_amount):
            self.bytes_downloaded += bytes_amount
            progress_value = self.bytes_downloaded / self.total_download_size if self.total_download_size > 0 else 0
            self.progress_bar.set(progress_value)
            self.update_idletasks()

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

    def start_scheduled_backup(self):
        if self.scheduled_job is not None:
            messagebox.showinfo("Info", "Scheduled backup already running")
            return

        try:
            interval = int(self.entry_interval.get())
            unit = self.interval_unit.get()
            delay = interval * TIME_CONVERSIONS[unit]
        except ValueError:
            messagebox.showerror("Error", "Invalid interval value")
            return

        self.scheduled_job = self.after(delay, self.scheduled_backup)
        self.log(f"Scheduled backup started (every {interval} {unit})")

    def stop_scheduled_backup(self):
        if self.scheduled_job:
            self.after_cancel(self.scheduled_job)
            self.scheduled_job = None
            self.log("Scheduled backup stopped")

    def scheduled_backup(self):
        self.run_backup()
        self.start_scheduled_backup()  # Reschedule

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
                self.entry_interval.delete(0, "end")
                self.entry_interval.insert(0, settings.get("interval", "60"))
                self.interval_unit.set(settings.get("interval_unit", "Minutes"))
                self.log("Loaded configuration from file")

    def save_config(self):
        config = configparser.ConfigParser()
        config["Settings"] = {
            "aws_access_key": self.entry_access.get(),
            "aws_secret_key": self.entry_secret.get(),
            "bucket_name": self.entry_bucket.get(),
            "computer_id": self.entry_computer_id.get(),
            "backup_dir": self.backup_dir_entry.get(),
            "restore_dir": self.restore_dir_entry.get(),
            "interval": self.entry_interval.get(),
            "interval_unit": self.interval_unit.get()
        }
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        self.log("Configuration saved")
        messagebox.showinfo("Success", "Settings saved successfully")


if __name__ == '__main__':
    app = S3BackupApp()
    app.mainloop()
