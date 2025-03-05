import os
import pathlib

import requests
from flask import Flask, render_template, session, abort, redirect, request, jsonify
from google.oauth2 import id_token, service_account
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import tempfile

app = Flask("Google Login App")
app.secret_key = "WarrantyMe.com"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
SCOPES = ['https://www.googleapis.com/auth/drive']

# SERVICE_ACCOUNT_FILE = 'service_account.json'

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
# flow = Flow.from_client_secrets_file(
#     client_secrets_file=client_secrets_file,
#     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
#     redirect_uri= REDIRECT_URI
# )

def create_flow():
    redirect_uri = os.getenv("REDIRECT_URI") #load redirect uri
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
            }
        },
        scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri=redirect_uri
    )
    return flow

flow = create_flow()
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function(*args, **kwargs) # Important to pass args and kwargs
    wrapper.__name__ = function.__name__ #keeps function name
    return wrapper

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }
    print("Callback Credentials:", session['credentials'])
    return redirect("/protected_area")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return render_template("welcome.html")

@app.route("/protected_area")
@login_is_required
def protected_area():
    return render_template("index.html")

def authenticate_service_account():
    service_account_info = {
        "type": "service_account",
        "project_id": "warrantyme-project",
        "private_key_id": os.getenv("SERVICE_ACCOUNT_PRIVATE_KEY_ID"),
        "private_key": os.getenv("SERVICE_ACCOUNT_PRIVATE_KEY"),
        "client_email": "warrantyme@warrantyme-project.iam.gserviceaccount.com",
        "client_id": os.getenv("SERVICE_ACCOUNT_CLIENT_ID"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/warrantyme%40warrantyme-project.iam.gserviceaccount.com",
        "universe_domain": "googleapis.com"
    }
    creds = service_account.Credentials.from_service_account_info(service_account_info, scopes=SCOPES)
    return creds

@app.route('/save_text', methods=['POST'])
@login_is_required
def save_text():
    text = request.form.get('text')
    folder_link = request.form.get('folderLink') #get folder link
    creds = authenticate_service_account()

    try:
        service = build('drive', 'v3', credentials=creds)

        # Extract folder ID from the link
        folder_id = folder_link.split('/')[-1]

        file_metadata = {
            'name': 'user_text.txt',
            'parents': [folder_id] #use folder id from input.
        }

        temp_file_path = tempfile.mktemp()

        with open(temp_file_path, 'w') as f:
            f.write(text)

        media = MediaFileUpload(temp_file_path, mimetype='text/plain')

        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()

        media.stream().close()
        os.remove(temp_file_path)

        return jsonify({'success': True, 'message': 'Text saved to Google Drive.'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error saving to Google Drive: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(debug=True)