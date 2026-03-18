import os
import socket
from contextlib import contextmanager
from io import BytesIO
from typing import Optional

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

SCOPES = ['https://www.googleapis.com/auth/drive.file']

# Base directory for dynamic paths (directory where this script lives)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@contextmanager
def _bypass_electrum_dns():
    """Temporarily restore the original socket.getaddrinfo so that
    Google API HTTP calls are not routed through Electrum's
    dnspython-based resolver (which requires Electrum's asyncio loop).
    """
    original = getattr(socket, '_getaddrinfo', None)
    if original is not None:
        patched = socket.getaddrinfo
        socket.getaddrinfo = original
        try:
            yield
        finally:
            socket.getaddrinfo = patched
    else:
        yield


def authenticate_with_google(credentials_path: Optional[str] = None, 
                             token_path: Optional[str] = None) -> Credentials:
    """
    Authenticate with Google Drive and return a Credentials object.
    """
    if credentials_path is None:
        credentials_path = os.path.join(BASE_DIR, "credentials.json")
    if token_path is None:
        token_path = os.path.join(BASE_DIR, "token.json")

    creds = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                with _bypass_electrum_dns():
                    creds.refresh(Request())
            except RefreshError:
                # Refresh token revoked — force full re-authentication
                creds = None
        if creds is None or not creds.valid:
            if not os.path.exists(credentials_path):
                raise FileNotFoundError(f"{credentials_path} not found.")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            with _bypass_electrum_dns():
                creds = flow.run_local_server(port=0)
        
        with open(token_path, 'w') as f:
            f.write(creds.to_json())

    return creds


def get_or_create_app_folder(creds, folder_name: str = "VirtualTokenApp") -> str:
    """
    Get or create the app folder in Google Drive root. Returns folder ID.
    """
    service = build('drive', 'v3', credentials=creds)
    
    with _bypass_electrum_dns():
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        results = service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        folders = results.get('files', [])
    
    if folders:
        folder_id = folders[0]['id']
        print(f"Found existing folder '{folder_name}' with ID: {folder_id}")
        return folder_id
    
    folder_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    with _bypass_electrum_dns():
        folder = service.files().create(body=folder_metadata, fields='id').execute()
    folder_id = folder.get('id')
    print(f"Created new folder '{folder_name}' with ID: {folder_id}")
    return folder_id


def upload_google_drive(enc_file: BytesIO, 
                        creds, 
                        file_name: str, 
                        folder_id: Optional[str] = None) -> str:
    """
    Uploads a BytesIO object to Google Drive.
    Returns the uploaded file ID.
    """
    service = build('drive', 'v3', credentials=creds)
    enc_file.seek(0)
    
    file_metadata = {'name': file_name}
    if folder_id:
        file_metadata['parents'] = [folder_id]
    
    media = MediaIoBaseUpload(enc_file, mimetype='application/octet-stream')
    with _bypass_electrum_dns():
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()

    print(f"File uploaded to Google Drive with ID: {file.get('id')}")
    return file.get('id')


def download_google_drive(file_link_path: Optional[str] = None,
                          download_dir: Optional[str] = None,
                          creds: Credentials = None,
                          file_name: Optional[str] = None) -> BytesIO:
    """
    Downloads a file from Google Drive given a file link in a text file.
    Returns a BytesIO containing the file content.
    """
    if file_link_path is None:
        file_link_path = os.path.join(BASE_DIR, "google_link.txt")
    if download_dir is None:
        download_dir = os.path.join(BASE_DIR, "downloads")
    os.makedirs(download_dir, exist_ok=True)

    with open(file_link_path, 'r') as f:
        file_id = f.read().split("/d/")[1].split('/')[0]

    if not file_name:
        # Default filename from file ID
        file_name = f"{file_id}.bin"
    file_path = os.path.join(download_dir, file_name)

    service = build("drive", "v3", credentials=creds)
    
    with open(file_path, "wb") as fh:
        request = service.files().get_media(fileId=file_id)
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        with _bypass_electrum_dns():
            while not done:
                _, done = downloader.next_chunk()

    print(f"File downloaded to {file_path}")

    # Return BytesIO object
    with open(file_path, "rb") as f:
        buffer = BytesIO(f.read())
    buffer.seek(0)
    return buffer
