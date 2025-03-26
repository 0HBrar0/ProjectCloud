import os
import boto3
import hashlib
import configparser
from plyer import notification
import logging
import time

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")

def get_s3_client(access_key, secret_key):
    return boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )

def compute_md5(file_path):
    """Compute MD5 hash of the file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def backup_directory(local_dir, bucket, access_key, secret_key, computer_folder="Default"):
    """Backup files to S3, skipping existing ones."""
    s3 = get_s3_client(access_key, secret_key)
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

    bytes_uploaded = 0
    for full_path, rel_path in file_list:
        s3_key = f"backup/{computer_folder}/{rel_path}".replace("\\", "/")
        local_md5 = compute_md5(full_path)

        try:
            # Check if file exists in S3 and compare MD5
            try:
                response = s3.head_object(Bucket=bucket, Key=s3_key)
                s3_md5 = response['Metadata'].get('file_md5', None)
                if s3_md5 == local_md5:
                    print(f"Skipping {full_path} (no changes)")
                    continue  # Skip the file if it hasn't changed
            except s3.exceptions.ClientError as e:
                # If file doesn't exist, continue with the upload
                if e.response['Error']['Code'] != '404':
                    print(f"Error checking {s3_key}: {e}")
                    continue

            # Upload the new or changed file
            s3.upload_file(
                full_path,
                bucket,
                s3_key,
                ExtraArgs={'Metadata': {'file_md5': local_md5}},
            )
            print(f"Uploaded {full_path} to s3://{bucket}/{s3_key}")
        except Exception as e:
            print(f"Error uploading {full_path}: {e}")

def load_config():
    """Load configuration values from the config file."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
        if "Settings" in config:
            settings = config["Settings"]
            aws_access_key = settings.get("aws_access_key", "")
            aws_secret_key = settings.get("aws_secret_key", "")
            bucket_name = settings.get("bucket_name", "")
            computer_id = settings.get("computer_id", "Default")
            backup_dir = settings.get("backup_dir", "")
            return aws_access_key, aws_secret_key, bucket_name, computer_id, backup_dir
    return None, None, None, None, None

def show_windows_notification(message):
    """Display a Windows notification with a custom title."""
    notification.notify(
        title="S3Sync",  # Title of the notification
        message=message,
        app_name="S3Sync"  # App name now set to "S3Sync" (this affects the application name above the notification)
    )

def log(message):
    """Log a message to the backup_log.txt file."""
    logging.info(message)

def main():
    # Configure logging
    logging.basicConfig(filename='backup_log.txt', level=logging.DEBUG, format="%(asctime)s - %(message)s")

    # Log the start of the backup process
    log("Backup script started.")

    # Load config values from config.ini
    access_key, secret_key, bucket, computer_folder, local_dir = load_config()

    if not access_key or not secret_key or not bucket or not local_dir:
        print("Error: Please provide valid AWS credentials, bucket name, and backup directory in config.ini.")
        log("Error: Invalid AWS credentials, bucket name, or backup directory.")
        return

    # Perform backup
    log(f"Starting backup for {local_dir}...")
    backup_directory(local_dir, bucket, access_key, secret_key, computer_folder)
    log("Backup completed successfully.")

    # Show Windows notification
    show_windows_notification("Backup completed successfully!")

    # Add a delay to keep the script running and show the notification
    time.sleep(5)  # Delay for 5 seconds

    # Log the completion of the script
    log("Backup script completed.")

if __name__ == "__main__":
    main()
