import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# --- Constants ---
DATA_FILE = "data.json"
USERS_FILE = "users.json"
FERNET_KEY_FILE = "fernet.key"

# --- Utility Functions ---
def generate_key():
    if not os.path.exists(FERNET_KEY_FILE):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(FERNET_KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

cipher = generate_key()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def load_json(file):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {}

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# --- Auto Logout After 5 Minutes ---
def auto_logout():
    if st.session_state.get("start_time") and datetime.now() - st.session_state.start_time > timedelta(minutes=5):
        st.session_state.is_logged_in = False
        st.session_state.username = ""
        st.session_state.start_time = None
        st.warning("⏳ Session expired due to 5 minutes of inactivity. Please log in again.")

# --- Session Initialization ---
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
    st.session_state.username = ""
    st.session_state.failed_attempts = 0
    st.session_state.lockout_until = None
    st.session_state.start_time = None

auto_logout()

# --- Auth Functions ---
def login(username, password):
    users = load_json(USERS_FILE)
    hashed = hash_passkey(password)
    if username in users and users[username] == hashed:
        st.session_state.is_logged_in = True
        st.session_state.username = username
        st.session_state.failed_attempts = 0
        st.session_state.start_time = datetime.now()
        return True
    return False

def logout():
    st.session_state.is_logged_in = False
    st.session_state.username = ""
    st.session_state.start_time = None

def register(username, password):
    users = load_json(USERS_FILE)
    if username in users:
        return False
    users[username] = hash_passkey(password)
    save_json(USERS_FILE, users)
    return True

# --- Encryption ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Global CSS Background Styling (applied to all pages) ---
st.markdown(
    """
    <style>
        .stApp {
            background: linear-gradient(to right, #ffe0ec, #ffe8f0);
            background-attachment: fixed;
        }

        .gradient-background {
            background: linear-gradient(135deg, #ff7eb3, #ff758c, #ffb199);
            padding: 100px 20px;
            border-radius: 10px;
            text-align: center;
            color: white;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            max-width: 700px;
            margin: 100px auto;
        }

        .gradient-background h1 {
            font-size: 3em;
            margin-bottom: 0.2em;
        }

        .gradient-background p {
            font-size: 1.5em;
        }
    </style>
    """,
    unsafe_allow_html=True
)

# --- Sidebar Styling ---     ##ddd6f3, #faaca8
st.markdown(
    """
    <style>
        [data-testid="stSidebar"] {
            background: linear-gradient(to bottom, #C9FFBF, #FFAFBD);     
        }
    </style>
    """,
    unsafe_allow_html=True,
)



# --- UI Pages ---
def home():
    st.markdown(
        """
        <div class="gradient-background">
            <h1>🔒 Secure Vault</h1>
            <p>Welcome to your encrypted vault. Please log in to continue.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

def register_page():
    st.subheader("📝 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and password:
            if register(username, password):
                st.success("✅ Registered successfully! Please log in.")
            else:
                st.error("❌ Username already exists.")
        else:
            st.warning("Please enter both fields.")

def login_page():
    st.subheader("🔐 Login")
    if st.session_state.lockout_until and datetime.now() < st.session_state.lockout_until:
        st.warning(f"Too many attempts. Try again at {st.session_state.lockout_until.strftime('%H:%M:%S')}")
        return

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if login(username, password):
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            st.error("❌ Invalid credentials.")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_until = datetime.now() + timedelta(minutes=1)
                st.warning("🔒 Too many failed attempts! Please wait 1 minute.")

def store_data():
    st.subheader("📂 Store Data")
    data = st.text_area("Enter data to encrypt")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            encrypted_text = encrypt_data(data)
            hashed_passkey = hash_passkey(passkey)

            vault = load_json(DATA_FILE)
            entry = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            vault.setdefault(st.session_state.username, []).append(entry)

            save_json(DATA_FILE, vault)
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.warning("Please fill in all fields.")

def retrieve_data():
    st.subheader("🔍 Retrieve Data")
    option = st.radio("Choose an option:", ["Select from stored data", "Paste encrypted string manually"])

    if option == "Select from stored data":
        vault = load_json(DATA_FILE).get(st.session_state.username, [])
        if not vault:
            st.info("You have no saved entries.")
            return

        if "decrypt_attempts" not in st.session_state:
            st.session_state.decrypt_attempts = 0
            st.session_state.decrypt_lockout_until = None

        if st.session_state.decrypt_lockout_until and datetime.now() < st.session_state.decrypt_lockout_until:
            st.warning(f"🔒 Too many failed attempts. Try again at {st.session_state.decrypt_lockout_until.strftime('%H:%M:%S')}")
            return

        index = st.selectbox("Select entry", range(len(vault)))
        passkey = st.text_input("Enter Passkey", type="password", key="stored_passkey")

        if st.button("Decrypt Selected"):
            entry = vault[index]
            if passkey:
                if hash_passkey(passkey) == entry["passkey"]:
                    st.session_state.decrypt_attempts = 0
                    decrypted = decrypt_data(entry["encrypted_text"])
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    st.session_state.decrypt_attempts += 1
                    st.error("❌ Incorrect passkey.")
                    if st.session_state.decrypt_attempts >= 3:
                        st.session_state.decrypt_lockout_until = datetime.now() + timedelta(minutes=1)
                        st.warning("🔒 Too many failed attempts! Please wait 1 minute.")
            else:
                st.warning("Passkey is required.")

    else:  # Manual input
        encrypted_input = st.text_area("Paste Encrypted Text")
        passkey = st.text_input("Enter Passkey", type="password", key="manual_passkey")

        if st.button("Decrypt Manual"):
            if encrypted_input and passkey:
                try:
                    decrypted = decrypt_data(encrypted_input)
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                except Exception:
                    st.error("❌ Failed to decrypt. Make sure the string and passkey are correct.")
            else:
                st.warning("Both fields are required.")

# --- Sidebar Navigation ---
st.sidebar.title("🔧 Menu")
page = st.sidebar.radio("Navigate", ["🏠 Home", "🔐 Login", "📝 Register", "📂 Store Data", "🔍 Retrieve Data", "🚪 Logout"])

# --- Navigation Logic ---
if page == "🏠 Home":
    home()
elif page == "🔐 Login":
    login_page()
elif page == "📝 Register":
    register_page()
elif page == "📂 Store Data":
    if st.session_state.is_logged_in:
        store_data()
    else:
        st.warning("⚠️ Please login to access this page.")
elif page == "🔍 Retrieve Data":
    if st.session_state.is_logged_in:
        retrieve_data()
    else:
        st.warning("⚠️ Please login to access this page.")
elif page == "🚪 Logout":
    if st.session_state.is_logged_in:
        logout()
        st.success("🔓 You have been logged out.")
    else:
        st.info("ℹ️ You are not logged in.")
    home()
