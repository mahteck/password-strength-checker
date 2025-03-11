import re
import streamlit as st
import random
import string
import json
import os
from cryptography.fernet import Fernet

# Generate or load encryption key
key_file = "encryption.key"
if not os.path.exists(key_file):
    with open(key_file, "wb") as f:
        f.write(Fernet.generate_key())
with open(key_file, "rb") as f:
    key = f.read()
cipher = Fernet(key)

# Password storage file
password_file = "passwords.json"
password_history = []

# Load saved passwords (Decrypt them properly)
if os.path.exists(password_file):
    with open(password_file, "rb") as f:
        encrypted_data = f.read()
        if encrypted_data:
            try:
                decrypted_data = cipher.decrypt(encrypted_data).decode()
                password_history = json.loads(decrypted_data) if decrypted_data else []
            except:
                password_history = []  # Reset if decryption fails
                with open(password_file, "wb") as f:
                    f.write(b"")

def save_password(password):
    global password_history  # Ensure global list is modified
    
    # Load existing passwords before modifying
    if os.path.exists(password_file):
        with open(password_file, "rb") as f:
            encrypted_data = f.read()
            if encrypted_data:
                try:
                    decrypted_data = cipher.decrypt(encrypted_data).decode()
                    password_history = json.loads(decrypted_data) if decrypted_data else []
                except:
                    password_history = []
    
    # Avoid duplicate password entries
    if password not in password_history:
        password_history.append(password)
    
    # Keep only the last 10 passwords
    if len(password_history) > 10:
        password_history.pop(0)
    
    # Encrypt and save the updated list
    encrypted_data = cipher.encrypt(json.dumps(password_history).encode())
    with open(password_file, "wb") as f:
        f.write(encrypted_data)

def clear_password_history():
    global password_history
    password_history = []
    with open(password_file, "wb") as f:
        f.write(b"")

def generate_password(length):
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(characters) for _ in range(length))

# List of common weak passwords
COMMON_PASSWORDS = {"password", "123456", "123456789", "qwerty", "abc123", "password1", "111111", "123123", "admin", "welcome"}

def check_password_strength(password, email):
    if password in password_history:
        return "⚠️ This password has been used before. Choose a new one.", []
    
    if password.lower() in COMMON_PASSWORDS:
        return "⚠️ This password is too common. Choose a more secure one.", []
    
    if email and password.lower() in email.lower():
        return "⚠️ Password should not contain your email.", []
    
    score = 0
    feedback = []
    
    # Length Check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Your password must be at least 8 characters long.")
    
    # Upper & Lowercase Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Use a mix of uppercase and lowercase letters.")
    
    # Digit Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9) for better security.")
    
    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*).")
    
    # Strength Rating
    if score == 4:
        save_password(password)
        return "✅ Your password is strong!", []
    elif score == 3:
        return "⚠️ Your password is moderate. Consider strengthening it.", feedback
    else:
        return "❌ Your password is weak. Follow the suggestions below to improve it.", feedback

# Streamlit App UI
st.set_page_config(page_title="Password Strength Meter", layout="wide")
st.title("🔐 Secure Password Strength Checker")
st.write("Test the strength of your password or generate a strong one!")

email = st.text_input("Enter your email (optional):", placeholder="e.g., user@example.com")
password = st.text_input("Enter your password:", type="password", placeholder="Type your password here...")

if password:
    strength, feedback = check_password_strength(password, email)
    st.subheader(strength)
    for msg in feedback:
        st.warning(msg)

# Password Length Selection
st.subheader("🔢 Generate a Strong Password")
length_option = st.radio("Choose password length:", [8, 12, 16, "Custom"])
custom_length = 12
if length_option == "Custom":
    custom_length = st.number_input("Enter custom length:", min_value=8, max_value=32, value=12)
else:
    custom_length = length_option

if st.button("Generate Secure Password"):
    generated_password = generate_password(custom_length)
    st.success("A strong password has been generated!")
    st.code(generated_password, language="text")
    save_password(generated_password)

# Sidebar for password history
st.sidebar.title("🔑 Password History")
if password_history:
    st.sidebar.write("Recently Used Passwords:")
    for idx, past_password in enumerate(password_history[::-1]):
        st.sidebar.text(f"{idx+1}. {past_password}")
    if st.sidebar.button("Clear Password History"):
        clear_password_history()
        st.sidebar.success("✅ Password history cleared!")
else:
    st.sidebar.info("No passwords stored yet.")

# Footer
st.markdown("---")
st.markdown("🔒 Keep your passwords unique and secure. Never reuse old passwords!")
st.markdown("""
    <hr>
    <p style='text-align: center; color: gray;'>© 2025 Secure Password Checker | Developed by Shoaib Munir</p>
""", unsafe_allow_html=True)
