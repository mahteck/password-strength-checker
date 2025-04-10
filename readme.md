# Secure Password Strength Checker

## Overview

This is a **Secure Password Strength Checker** built using **Streamlit**. It helps users evaluate the strength of their passwords, generate strong passwords, and store recently used passwords securely.

## Features

- **Password Strength Checker:**
  - Analyzes passwords based on length, uppercase/lowercase letters, numbers, and special characters.
  - Provides feedback and suggestions to improve weak passwords.
- **Password Generator:**
  - Generates strong passwords with customizable length.
  - Ensures generated passwords meet security standards.
- **Password Storage:**
  - Encrypts and stores the last 10 used passwords.
  - Prevents password reuse.
  - Allows clearing password history.

## Installation

### Prerequisites

Ensure you have **Python 3.7+** installed.

### Steps to Install & Run

1. Clone this repository:
   ```sh
   git clone https://github.com/mahteck/password-strength-checker.git
   cd password-strength-checker
   ```
2. Install required dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Run the Streamlit app:
   ```sh
   streamlit run password_manager.py
   ```

## Dependencies

- **Streamlit** - For building the UI
- **Cryptography** - For secure password storage
- **JSON & OS** - For file handling

## Usage

1. Enter your password to check its strength.
2. View strength feedback and suggestions.
3. Generate a secure password if needed.
4. Store and view recently used passwords in the sidebar.
5. Clear password history when necessary.

## Security Measures

- Uses **encryption (Fernet)** to store passwords securely.
- Detects weak and commonly used passwords.
- Prevents storing duplicate passwords.

## Live Demo

Check out the live version of the project: [Website Link](http://mahteck.com)

## License

This project is licensed under the MIT License.

## Author

**Shoaib Munir**

## GitHub Repository

Find the project on GitHub: [GitHub Repository](https://github.com/mahteck/password-strength-checker)

## Contributions

Feel free to contribute! Fork the repo, create a new branch, and submit a PR.

---

**Note:** Always store your passwords securely and never reuse weak passwords!

