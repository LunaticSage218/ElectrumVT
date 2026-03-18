import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/drive.file']

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_PATH = os.path.join(BASE_DIR, "credentials.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.json")


def authenticate():
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print("Failed to refresh token:", e)
                creds = None
        if creds is None or not creds.valid:
            if not os.path.exists(CREDENTIALS_PATH):
                raise FileNotFoundError(f"{CREDENTIALS_PATH} not found.")
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
            creds = flow.run_console()  # Use console instead of local server
        with open(TOKEN_PATH, 'w') as f:
            f.write(creds.to_json())

    return creds


def test_drive_api():
    creds = authenticate()
    service = build('drive', 'v3', credentials=creds)

    try:
        # List first 5 files in your Drive to test connectivity
        results = service.files().list(pageSize=5, fields="files(id, name)").execute()
        items = results.get('files', [])
        if not items:
            print("Connected! No files found in Drive.")
        else:
            print("Connected! First 5 files:")
            for item in items:
                print(f"{item['name']} (ID: {item['id']})")
    except Exception as e:
        print("Failed to connect to Drive API:", e)


if __name__ == "__main__":
    test_drive_api()