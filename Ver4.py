import os
import threading
import configparser
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import customtkinter as ctk
from tkinter import filedialog, messagebox, scrolledtext

# Use a configuration file to persist settings
CONFIG_FILE = "config.ini"

# Conversion factors for backup interval
TIME_CONVERSIONS = {
    "Seconds": 1000,
    "Minutes": 60000,
    "Hours": 3600000,
    "Days": 86400000
}

# Set CustomTkinter appearance and theme
ctk.set_appearance_mode("dark")  # Options: "dark", "light", "system"
ctk.set_default_color_theme("blue")  # You can choose "blue", "green", "dark-blue", etc.


class S3BackupApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("S3Sync")
        self.geometry("800x600")
        self.resizable(True, True)

        # Create a main frame with padding
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Create a grid inside main_frame
        self.main_frame.columnconfigure(1, weight=1)
        for i in range(15):
            self.main_frame.rowconfigure(i, weight=1)

        # AWS Credentials
        ctk.CTkLabel(self.main_frame, text="AWS Access Key ID:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_access = ctk.CTkEntry(self.main_frame, width=300)
        self.entry_access.grid(row=0, column=1, padx=5, pady=5)

        ctk.CTkLabel(self.main_frame, text="AWS Secret Access Key:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.entry_secret = ctk.CTkEntry(self.main_frame, width=300, show="*")
        self.entry_secret.grid(row=1, column=1, padx=5, pady=5)

        ctk.CTkLabel(self.main_frame, text="S3 Bucket Name:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.entry_bucket = ctk.CTkEntry(self.main_frame, width=300)
        self.entry_bucket.grid(row=2, column=1, padx=5, pady=5)

        # Computer ID Field
        ctk.CTkLabel(self.main_frame, text="Username").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.computer_id = ctk.StringVar()
        self.entry_computer_id = ctk.CTkEntry(self.main_frame, textvariable=self.computer_id, width=300)
        self.entry_computer_id.grid(row=3, column=1, padx=5, pady=5)

        # Backup Directory
        ctk.CTkLabel(self.main_frame, text="Local Backup Directory:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.backup_dir = ctk.StringVar()
        self.entry_backup_dir = ctk.CTkEntry(self.main_frame, textvariable=self.backup_dir, width=300)
        self.entry_backup_dir.grid(row=4, column=1, padx=5, pady=5)
        self.btn_select_backup = ctk.CTkButton(self.main_frame, text="Select Directory",
                                               command=self.select_backup_directory)
        self.btn_select_backup.grid(row=4, column=2, padx=5, pady=5)

        # Restore Directory
        ctk.CTkLabel(self.main_frame, text="Local Restore Directory:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
        self.restore_dir = ctk.StringVar()
        self.entry_restore_dir = ctk.CTkEntry(self.main_frame, textvariable=self.restore_dir, width=300)
        self.entry_restore_dir.grid(row=5, column=1, padx=5, pady=5)
        self.btn_select_restore = ctk.CTkButton(self.main_frame, text="Select Directory",
                                                command=self.select_restore_directory)
        self.btn_select_restore.grid(row=5, column=2, padx=5, pady=5)

        # Backup Interval and Unit
        ctk.CTkLabel(self.main_frame, text="Backup Interval:").grid(row=6, column=0, sticky="w", padx=5, pady=5)
        self.entry_interval = ctk.CTkEntry(self.main_frame, width=100)
        self.entry_interval.grid(row=6, column=1, sticky="w", padx=5, pady=5)
        self.entry_interval.insert(0, "60")
        self.interval_unit = ctk.StringVar(value="Minutes")
        self.unit_menu = ctk.CTkOptionMenu(self.main_frame, variable=self.interval_unit,
                                           values=["Seconds", "Minutes", "Hours", "Days"])
        self.unit_menu.grid(row=6, column=2, padx=5, pady=5)

        # Action Buttons
        self.btn_backup_now = ctk.CTkButton(self.main_frame, text="Start Backup Now", command=self.start_backup_thread)
        self.btn_backup_now.grid(row=7, column=0, columnspan=3, pady=5)

        self.btn_restore = ctk.CTkButton(self.main_frame, text="Restore Backup", command=self.start_restore_thread)
        self.btn_restore.grid(row=8, column=0, columnspan=3, pady=5)

        self.btn_start_sched = ctk.CTkButton(self.main_frame, text="Start Scheduled Backup",
                                             command=self.start_scheduled_backup)
        self.btn_start_sched.grid(row=9, column=0, columnspan=3, pady=5)

        self.btn_stop_sched = ctk.CTkButton(self.main_frame, text="Stop Scheduled Backup",
                                            command=self.stop_scheduled_backup)
        self.btn_stop_sched.grid(row=10, column=0, columnspan=3, pady=5)

        self.btn_save_config = ctk.CTkButton(self.main_frame, text="Save Settings", command=self.save_config)
        self.btn_save_config.grid(row=11, column=0, columnspan=3, pady=5)

        # Log Output - using a scrolled text widget
        ctk.CTkLabel(self.main_frame, text="Log Output:").grid(row=12, column=0, sticky="w", padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(self.main_frame, width=70, height=10, state="disabled", bg="#1f1f1f",
                                                  fg="white")
        self.log_text.grid(row=13, column=0, columnspan=3, padx=5, pady=5)

        self.scheduled_job = None

        # Load configuration if available
        self.load_config()

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def select_backup_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.backup_dir.set(directory)
            self.log(f"Selected backup directory: {directory}")

    def select_restore_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.restore_dir.set(directory)
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

    def backup_directory(self, local_dir, bucket, base_prefix="backup/"):
        computer_folder = self.computer_id.get().strip() or "Default"
        prefix = os.path.join(base_prefix, computer_folder) + "/"
        s3 = self.get_s3_client()
        if s3 is None:
            return
        for root, dirs, files in os.walk(local_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, local_dir)
                s3_key = os.path.join(prefix, rel_path).replace("\\", "/")
                try:
                    s3.upload_file(full_path, bucket, s3_key)
                    self.log(f"Uploaded {full_path} to s3://{bucket}/{s3_key}")
                except (NoCredentialsError, ClientError) as e:
                    self.log(f"Error uploading {full_path}: {e}")

    def restore_backup(self, bucket, base_prefix="backup/"):
        s3 = self.get_s3_client()
        if s3 is None:
            return
        restore_dir = self.restore_dir.get()
        if not restore_dir:
            messagebox.showerror("Error", "Please select a restore directory.")
            return
        computer_folder = self.computer_id.get().strip() or "Default"
        prefix = os.path.join(base_prefix, computer_folder) + "/"
        paginator = s3.get_paginator('list_objects_v2')
        try:
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        s3_key = obj['Key']
                        rel_path = os.path.relpath(s3_key, prefix)
                        local_file_path = os.path.join(restore_dir, rel_path)
                        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
                        try:
                            s3.download_file(bucket, s3_key, local_file_path)
                            self.log(f"Downloaded {s3_key} to {local_file_path}")
                        except Exception as e:
                            self.log(f"Error downloading {s3_key}: {e}")
            messagebox.showinfo("Restore", "Restore completed successfully!")
        except Exception as e:
            messagebox.showerror("Restore Error", str(e))

    def start_backup_thread(self):
        threading.Thread(target=self.run_backup, daemon=True).start()

    def run_backup(self):
        local_dir = self.backup_dir.get()
        bucket = self.entry_bucket.get().strip()
        if not local_dir or not bucket:
            messagebox.showerror("Error", "Please select a backup directory and enter a bucket name.")
            return
        self.log("Starting backup...")
        try:
            self.backup_directory(local_dir, bucket)
            self.log("Backup completed successfully!")
            messagebox.showinfo("Backup", "Backup completed successfully!")
        except Exception as e:
            self.log(f"Backup error: {e}")
            messagebox.showerror("Backup Error", str(e))

    def start_restore_thread(self):
        threading.Thread(target=self.run_restore, daemon=True).start()

    def run_restore(self):
        bucket = self.entry_bucket.get().strip()
        if not bucket:
            messagebox.showerror("Error", "Please enter a bucket name.")
            return
        self.log("Starting restore...")
        try:
            self.restore_backup(bucket)
        except Exception as e:
            self.log(f"Restore error: {e}")
            messagebox.showerror("Restore Error", str(e))

    def scheduled_backup(self):
        self.log("Scheduled backup triggered.")
        self.run_backup()
        try:
            interval_value = int(self.entry_interval.get())
            unit = self.interval_unit.get()
            factor = TIME_CONVERSIONS.get(unit, 60000)
            delay = interval_value * factor
        except ValueError:
            messagebox.showerror("Error", "Invalid interval value. Please enter a number.")
            return
        self.scheduled_job = self.after(delay, self.scheduled_backup)

    def start_scheduled_backup(self):
        if self.scheduled_job is not None:
            messagebox.showinfo("Scheduled Backup", "A scheduled backup is already running.")
            return
        self.scheduled_backup()
        self.log("Scheduled backup started.")
        messagebox.showinfo("Scheduled Backup", "Scheduled backup started.")

    def stop_scheduled_backup(self):
        if self.scheduled_job is not None:
            self.after_cancel(self.scheduled_job)
            self.scheduled_job = None
            self.log("Scheduled backup stopped.")
            messagebox.showinfo("Scheduled Backup", "Scheduled backup stopped.")
        else:
            messagebox.showinfo("Scheduled Backup", "No scheduled backup is running.")

    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
            if "Settings" in config:
                settings = config["Settings"]
                self.entry_access.delete(0, ctk.END)
                self.entry_access.insert(0, settings.get("aws_access_key", ""))
                self.entry_secret.delete(0, ctk.END)
                self.entry_secret.insert(0, settings.get("aws_secret_key", ""))
                self.entry_bucket.delete(0, ctk.END)
                self.entry_bucket.insert(0, settings.get("bucket_name", ""))
                self.backup_dir.set(settings.get("backup_directory", ""))
                self.restore_dir.set(settings.get("restore_directory", ""))
                self.entry_interval.delete(0, ctk.END)
                self.entry_interval.insert(0, settings.get("backup_interval", "60"))
                self.interval_unit.set(settings.get("interval_unit", "Minutes"))
                self.computer_id.set(settings.get("computer_id", ""))
                self.log("Configuration loaded from config.ini")

    def save_config(self):
        config = configparser.ConfigParser()
        config["Settings"] = {
            "aws_access_key": self.entry_access.get().strip(),
            "aws_secret_key": self.entry_secret.get().strip(),
            "bucket_name": self.entry_bucket.get().strip(),
            "backup_directory": self.backup_dir.get(),
            "restore_directory": self.restore_dir.get(),
            "backup_interval": self.entry_interval.get().strip(),
            "interval_unit": self.interval_unit.get(),
            "computer_id": self.computer_id.get().strip()
        }
        with open(CONFIG_FILE, "w") as configfile:
            config.write(configfile)
        self.log("Configuration saved to config.ini")
        messagebox.showinfo("Save Settings", "Settings saved successfully.")


if __name__ == '__main__':
    app = S3BackupApp()
    app.mainloop()
