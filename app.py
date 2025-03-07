from ast import If
from flask import Flask
import imaplib
import requests
import os
import hashlib
import email
import gdown
from email.header import decode_header
import re
import base64
from zipfile import ZipFile, BadZipFile
from email.header import decode_header
import zipfile
import pyzipper
import time
import subprocess
import getpass

def download_from_google_drive(drive_link, save_path=None, password=None):
    """
    Downloads a file from a Google Drive link and saves it to the specified directory.
    If the file is a ZIP, it is then send for extraction and Virus Total scanning.
    
    Parameters:
        drive_link (str): The Google Drive link to the file.
        save_path (str): The directory where the file will be saved. Default is the predefined path.
        password (str, optional): Password for extracting the ZIP file (if applicable).
    """
    
    # Ensure the save directory exists
    os.makedirs(save_path, exist_ok=True)
    
    # Extract the file ID from the Google Drive link
    match = re.search(r"[-\w]{25,}", drive_link)
    if not match:
        print("Error: The provided Google Drive link is invalid.")
        return
    
    file_id = match.group(0)
    file_name = f"{file_id}.zip"  # Assuming the file is a ZIP
    full_path = os.path.join(save_path, file_name)
    
    try:
        print(f"Starting download from Google Drive...")
        print(f"Fetching file from: {drive_link}")
        
        # Download the file using gdown
        gdown.download(id=file_id, output=full_path, quiet=False)
        
        print(f"Download complete! File saved at: {full_path}")
        
        # Extract and scan the ZIP file after downloading
        extract_and_scan_zip_file(full_path, save_path, password)
    except Exception as e:
        print(f"An error occurred during the download: {e}")


def connect_to_email(email_user, email_password, imap_url="imap.gmail.com"):
    """
    Connects to an email server using IMAP and logs in with the provided credentials.

    Parameters:
        email_user (str): The email address to log in with.
        email_password (str): The password for the email account.
        imap_url (str): The IMAP server URL (default is Gmail's IMAP server).

    Returns:
        Returns the email server connection object if successful, otherwise None.
    """
    try:
        print("Attempting to connect to the email server...")
        
        # Establish a secure connection to the IMAP server
        mail = imaplib.IMAP4_SSL(imap_url)
        
        # Attempt to log in with provided credentials
        mail.login(email_user, email_password)
        return mail
    except Exception as e:
    
        return None


def fetch_unread_emails(mail):
    """
    Retrieves unread emails from the inbox.

    Parameters:
        mail (imaplib.IMAP4_SSL): The connected email server object.

    Returns:
        list: A list of unread email IDs. Returns an empty list if an error occurs.
    """
    try:
        print("Accessing inbox to fetch unread emails...")

        # Select the inbox
        mail.select("inbox")

        # Search for all unread (unseen) emails
        status, messages = mail.search(None, 'UNSEEN')

        # Extract email IDs from the response
        email_ids = messages[0].split()

        print(f"Total unread emails found: {len(email_ids)}")
        return email_ids
    except Exception as e:
        print(f"Failed to fetch unread emails. Error: {e}")
        return []


def has_attachments(msg):
    """
    Checks if an email message contains attachments.

    Parameters:
        msg (email.message.Message): The email message object.

    Returns:
        bool: True if the email has attachments, otherwise False.
    """
    try:
        # If the email has multiple parts, iterate through them
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", "")).lower()
                if "attachment" in content_disposition:
                    return True
        else:
            # Check the single-part email for attachments
            content_disposition = str(msg.get("Content-Disposition", "")).lower()
            if "attachment" in content_disposition:
                return True

        return False  # No attachments found
    except Exception as e:
        print(f"Error checking for attachments: {e}")
        return False

def is_zip_file(filename):
    """
    Checks if a given filename has a .zip extension.

    Parameters:
        filename (str): The name of the file.

    Returns:
        bool: True if the file is a ZIP file, otherwise False.
    """
    try:
        # Ensure the filename is a valid string
        if not isinstance(filename, str) or not filename.strip():
            return False
        
        # Check if the file extension is .zip (case-insensitive)
        return filename.lower().endswith('.zip')
    except Exception as e:
        print(f"Error checking file type: {e}")
        return False

def get_file_sha256(file_path):
    """
    Computes the SHA-256 hash of a given file.

    Parameters:
        file_path (str): The path to the file.

    Returns:
        str: The SHA-256 hash of the file as a hexadecimal string.
        None: If an error occurs (e.g., file not found).
    """
    try:
        hasher = hashlib.sha256()

        # Open the file in binary mode and read in chunks
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):  # Read 8 KB at a time
                hasher.update(chunk)

        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
    except Exception as e:
        print(f"Error calculating SHA-256 hash: {e}")

    return None  # Return None if an error occurs



def scan_file_virustotal(file_path, api_key=None):
    """
    Uploads a file to VirusTotal for scanning.

    Parameters:
        file_path (str): The path of the file to scan.
        api_key (str): The VirusTotal API key.

    Returns:
        str: The scan ID if the upload is successful.
        None: If an error occurs.
    """
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    try:
        with open(file_path, "rb") as file:
            files = {"file": (file_path, file)}
            
            print(f"Uploading file '{file_path}' to VirusTotal for scanning...")
            response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            json_response = response.json()
            scan_id = json_response.get('data', {}).get('id')

            if scan_id:
                print(f"File uploaded successfully! Scan ID: {scan_id}")
                return scan_id
            else:
                print("File uploaded, but scan ID not found in response.")
        else:
            print(f"Error uploading file: {response.status_code} - {response.text}")

    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
    except requests.RequestException as e:
        print(f"Network error while uploading file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    return None  # Return None if an error occured


def get_virustotal_report(scan_id, file_path, api_key, max_wait_time=300, check_interval=10):
    """
    Retrieves a VirusTotal scan report for a given file.

    Parameters:
        scan_id (str): The scan ID from the VirusTotal scan.
        file_path (str): The path of the file to retrieve the report for.
        api_key (str): The VirusTotal API key.
        max_wait_time (int): The maximum time (in seconds) to wait for the report. Default is 300 seconds.
        check_interval (int): Time interval (in seconds) between report checks. Default is 10 seconds.

    Returns:
        tuple: (verdict, last_analysis_stats) if a report is found, otherwise (None, None).
    """
    if not scan_id and not file_path:
        print("Error: No scan ID or file path provided. Skipping VirusTotal report.")
        return None, None

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    # Calculate the file's SHA-256 hash
    file_hash = get_file_sha256(file_path)
    if not file_hash:
        print("Error: Unable to compute SHA-256 hash. Skipping VirusTotal report.")
        return None, None

    print(f"File Hash: {file_hash}")
    print(f"Attempting to retrieve report using SHA-256: {file_hash}")

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    time.sleep(30)
    while True:
        
        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 404:
                print("File not found on VirusTotal. It may not have been uploaded yet.")
            else:
                response.raise_for_status()
                json_response = response.json()
                attributes = json_response.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
            
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving the report: {e}")
            return None, None
        
        total_scanned = sum([
            last_analysis_stats.get('malicious', 0),
            last_analysis_stats.get('suspicious', 0),
            last_analysis_stats.get('harmless', 0),
            last_analysis_stats.get('undetected', 0),
            last_analysis_stats.get('timeout', 0)
        ])
        if total_scanned>50:
            break
        else: 
            print("Report not ready yet. trying again.")
            time.sleep(180)

    

    # Display the scan results
    print("\nVirusTotal Scan Summary:")
    print(f"  Malicious: {last_analysis_stats.get('malicious', 0)}")
    print(f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}")
    print(f"  Undetected: {last_analysis_stats.get('undetected', 0)}")
    print(f"  Harmless: {last_analysis_stats.get('harmless', 0)}")
    print(f"  Timeout: {last_analysis_stats.get('timeout', 0)}")
    print(f"  Type Unsupported: {last_analysis_stats.get('type-unsupported', 0)}")

    # Determine the overall verdict based on scan results
    if last_analysis_stats.get("malicious", 0) > 0:
        verdict = "Malicious"
    elif last_analysis_stats.get("suspicious", 0) > 0:
        verdict = "Suspicious"
    elif last_analysis_stats.get("undetected", 0) > 0:
        verdict = "Undetected (Not flagged by engines)"
    else:
        verdict = "Harmless or Safe"

    print(f"\nFinal Verdict: {verdict}")
    return verdict, last_analysis_stats

    


def extract_and_scan_zip_file(zip_path, extract_folder=None, password=None):
    """
    Extracts a ZIP file, repacks it without a password, and scans it with VirusTotal.

    Parameters:
        zip_path (str): Path to the ZIP file.
        extract_folder (str): Directory where files should be extracted. 
        password (str, optional): Password for encrypted ZIP files.

    Returns:
        None
    """
    # Generate the extraction folder based on the ZIP file name
    base_name = os.path.splitext(os.path.basename(zip_path))[0]
    zip_extract_folder = os.path.join(extract_folder, base_name)

    # Ensure the extraction folder exists
    os.makedirs(zip_extract_folder, exist_ok=True)

    try:
        # Extract the ZIP file
        with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
            if password:
                zip_ref.pwd = password.encode()  # Set password if provided
            zip_ref.extractall(zip_extract_folder)
            print(f"Successfully extracted ZIP file to: {zip_extract_folder}")

        # Create a new ZIP file (without password) containing extracted files
        new_zip_path = os.path.join(extract_folder, f"{base_name}_repacked.zip")
        with zipfile.ZipFile(new_zip_path, 'w', zipfile.ZIP_DEFLATED) as new_zip:
            for root, _, files in os.walk(zip_extract_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, zip_extract_folder)
                    new_zip.write(file_path, arcname)

        print(f"Recompressed extracted files into: {new_zip_path}")

        # Scan the new ZIP file (without password) with VirusTotal
        print(f"Scanning new ZIP file {new_zip_path} with VirusTotal...")
        scan_id = scan_file_virustotal(new_zip_path,VIRUS_TOTAL_API_KEY)
        if scan_id:
            get_virustotal_report(scan_id, new_zip_path,VIRUS_TOTAL_API_KEY)

    except pyzipper.BadZipFile:
        print(f"Error: {zip_path} is not a valid ZIP file.")
    except RuntimeError:
        print(f"Error: Incorrect password or extraction failed for {zip_path}.")
    except Exception as e:
        print(f"Unexpected error: {e}")

def download_and_extract_attachments(mail, email_id, download_folder=None,
    extract_folder=None, password=None):
    """
    Downloads ZIP attachments from an email, extracts them, and scans them with VirusTotal.

    Parameters:
        mail (imaplib.IMAP4_SSL): The email server connection.
        email_id (str): The ID of the email to process.
        download_folder (str): Folder to save downloaded attachments.
        extract_folder (str): Folder where extracted files will be stored.
        password (str, optional): Password for encrypted ZIP files.

    Returns:
        None
    """
    # Ensure download and extraction folders exist
    os.makedirs(download_folder, exist_ok=True)
    os.makedirs(extract_folder, exist_ok=True)

    try:
        # Fetch the email by ID
        status, msg_data = mail.fetch(email_id, "(RFC822)")
        if status != "OK":
            print(f"Failed to fetch email with ID: {email_id}")
            return

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                # Decode the email subject
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else 'utf-8')
                #print(f"Processing Email - Subject: {subject}")

                # Process attachments if the email is multipart
                if msg.is_multipart():
                    for part in msg.walk():
                        content_disposition = str(part.get("Content-Disposition"))
                        if "attachment" in content_disposition:
                            filename = part.get_filename()
                            if filename and is_zip_file(filename):  # Check if it's a ZIP file
                                filepath = os.path.join(download_folder, filename)
                                
                                # Download the ZIP file
                                with open(filepath, "wb") as f:
                                    f.write(part.get_payload(decode=True))
                                print(f"Downloaded ZIP attachment: {filename}")
                                ZIP_PASSWORD = getpass.getpass(f"Enter the password for ZIP file '{filename}': ")
                                            
                                # Extract the ZIP file and scan it
                                extract_and_scan_zip_file(filepath, extract_folder, ZIP_PASSWORD)

                else:
                    # Handle single-part emails with attachments
                    content_disposition = str(msg.get("Content-Disposition"))
                    if "attachment" in content_disposition:
                        filename = msg.get_filename()
                        if filename and is_zip_file(filename):
                            filepath = os.path.join(download_folder, filename)

                            # Download the ZIP file
                            with open(filepath, "wb") as f:
                                f.write(msg.get_payload(decode=True))
                            print(f"Downloaded ZIP attachment: {filename}")

                            # Extract the ZIP file and scan it
                            extract_and_scan_zip_file(filepath, extract_folder, password)

        # Mark the email as read (processed)
        mail.store(email_id, '+FLAGS', '\\Seen')
        #print(f"Email {email_id} processed and marked as read.")

    except imaplib.IMAP4.error as e:
        print(f"IMAP error while processing email {email_id}: {e}")
    except Exception as e:
        print(f"Unexpected error while processing email {email_id}: {e}")
        

if __name__ == "__main__":
    # Define the default save path
    SAVE_PATH = r"C:\Users\anika\Downloads\Test123"
    
    # Get user credentials and API key securely
    EMAIL_USER = input("Enter your email address: ")
    EMAIL_PASSWORD = getpass.getpass("Enter your email password (input hidden): ")
    VIRUS_TOTAL_API_KEY = getpass.getpass("Enter your VirusTotal API key (input hidden): ")

    print("\nConnecting to email server...")
    mail = connect_to_email(EMAIL_USER, EMAIL_PASSWORD)

    if not mail:
        print("Failed to connect to the email server. Please check your credentials.")
    else:
        print("Successfully connected to the email server.")

        # Fetch unread emails
        email_ids = fetch_unread_emails(mail)

        if not email_ids:
            print("No unread emails found.")
        else:
            print(f"Found {len(email_ids)} unread email(s). Processing...")

            # Process each unread email one by one
            for email_id in email_ids:
                try:
                    # Fetch the email content
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    if status != "OK":
                        print(f"Error fetching email ID {email_id}. Skipping...")
                        continue

                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])

                            # Decode the email subject
                            subject, encoding = decode_header(msg["Subject"])[0]
                            if isinstance(subject, bytes):
                                subject = subject.decode(encoding if encoding else 'utf-8')
                            print(f"\nProcessing email - Subject: {subject}")

                            # Extract email body text
                            email_body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() == "text/plain":
                                        email_body += part.get_payload(decode=True).decode(errors="ignore")
                            else:
                                email_body = msg.get_payload(decode=True).decode(errors="ignore")

                            # Check for Google Drive links in the email body
                            drive_links = re.findall(r'https://drive\.google\.com/[^\s]+', email_body)
                            if drive_links:
                                for link in drive_links:
                                    print(f"Found Google Drive link: {link}")
                                    ZIP_PASSWORD = getpass.getpass(f"Enter the password for ZIP file in email '{subject}': ")
                                    download_from_google_drive(link, save_path=SAVE_PATH, password=ZIP_PASSWORD)

                            # Check if the email has attachments
                            if has_attachments(msg):
                                print("Email contains attachments. Checking for ZIP files...")
                                download_and_extract_attachments(mail, email_id, SAVE_PATH,SAVE_PATH, password=None)
                            else:
                                print("No attachments found in this email.")

                    # Mark email as read after processing
                    mail.store(email_id, '+FLAGS', '\\Seen')

                except Exception as e:
                    print(f"Error processing email ID {email_id}: {e}")

            print("\nAll unread emails processed.")

        # Logout after processing
        mail.logout()
        print("Logged out from email server.")
