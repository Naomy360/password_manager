
# Password Manager Application

This project is a secure password manager built using JavaScript, HTML, and CSS. It includes various features such as generating secure passwords, checking for password breaches, encrypting and saving multiple passwords, and securely sharing and decrypting passwords. The backend uses Express.js and communicates with the "Have I Been Pwned" API to check if a password has been compromised. Below is a detailed explanation of the application’s features and how each one is implemented.

## Application Features

### 1. **Password Generation**

The application provides functionality to generate strong and secure passwords based on user-defined criteria. Users can customize the password length (from 8 to 32 characters) and choose to include:

- **Uppercase Letters**
- **Numbers**
- **Special Characters**

The password is generated using cryptographic randomness via the `crypto.getRandomValues` method in JavaScript, ensuring the password is unpredictable and resistant to brute-force attacks.
-- For security, the generated password clears after 30 seconds.

#### How It Works:
- When the user selects the password length and options, the application generates a password using the selected character sets.
- It calculates the entropy of the password to determine its strength (Weak, Moderate, Strong), which is displayed using a progress bar.
- The generated password is shown in an input field, and the user can copy it to their clipboard for use.
- For security, the generated password clears after 30 seconds.

### 2. **Password Strength Checking**

Users can check the strength of a password to assess how secure it is. The strength of a password is evaluated based on entropy, which is a measure of randomness.

#### How It Works:
- The user enters a password, and the entropy is calculated by measuring the unique characters and the length of the password.
- The entropy value is then used to assess whether the password is weak, moderate, or strong.
- The result is displayed in both a textual description (e.g., "Password Strength: Strong") and visually in a progress bar.

### 3. **Check for Breached Passwords**

The app allows users to check if their password has been exposed in a data breach using the "Have I Been Pwned" API. It uses a hashing technique (SHA-1) to securely check if the password has been compromised without exposing the actual password.

#### How It Works:
- The password entered by the user is hashed using the SHA-1 algorithm.
- The first five characters of the hashed password (the prefix) are sent to the "Have I Been Pwned" API, which returns a list of hashes with the same prefix.
- The application then checks if the remaining characters (suffix) match any entries from the API. If there’s a match, the password is considered breached.
- The result, including the number of breaches, is displayed to the user.

### 4. **Encrypt and Save Multiple Passwords**

This feature enables users to securely save multiple passwords with their associated account labels. The passwords are encrypted using the **AES-GCM** encryption algorithm, which provides both confidentiality and data integrity.

#### How It Works:
- The user enters the number of passwords they want to save and fills in the account labels and passwords.
- The user also provides an encryption key, which is processed using the PBKDF2 key derivation function (with a salt) to create a stronger encryption key.
- The passwords are then encrypted with AES-GCM and saved into a JSON file that can be downloaded securely.

### 5. **Secure Sharing of Encrypted Passwords**

The app allows users to securely share a password by encrypting it with **RSA** public key encryption. The user generates a key pair (public and private) and uses the public key to encrypt a password, which can then be shared securely with others.

#### How It Works:
- The user enters the password they want to share.
- The app generates an RSA public/private key pair. The public key is used to encrypt the password, and the encrypted password is then saved into a JSON file, which can be downloaded and shared with others.
- The private key is stored securely for later use and can be used to decrypt the password.

### 6. **Decrypt Shared Passwords**

Users can decrypt passwords that have been shared with them by using the RSA private key.

#### How It Works:
- The user uploads the encrypted password file and provides their private key.
- The app uses the private key to decrypt the password.
- The decrypted password is displayed to the user.

### 7. **Backend for Password Breach Checking**

The application uses a backend server to interact with the "Have I Been Pwned" API. The backend is built with **Express.js** and serves as a proxy for checking password breaches.

#### How It Works:
- The backend listens for requests at `http://localhost:3000/pwned/${prefix}` and fetches the breach data from the "Have I Been Pwned" API.
- The frontend sends the hashed password prefix to the backend, which then queries the API for matching breaches.

### Key Technologies Used

- **Frontend**: JavaScript, HTML, CSS
- **Backend**: Node.js, Express.js, "Have I Been Pwned" API
- **Encryption**: AES-GCM (for password encryption), RSA (for secure sharing), PBKDF2 (for key derivation)
- **Hashing**: SHA-1 (for password breach checking)



## Prerequisites

To run this project locally, you will need:

- A modern web browser (e.g., Chrome, Firefox, Safari)
- [Git](https://git-scm.com/downloads) installed on your computer
- [Node.js](https://nodejs.org/) (for backend or optional local server)

## Running the Application

### Step 1: Clone the Repository

Open a terminal and run the following command to clone the project:

```bash
git clone https://github.com/Naomy360/password_manager.git

The backend uses Node.js and Express. To install the necessary dependencies, run:
npm install
Since you are running locally, ensure the API URL in script.js points to your local server. Look for the following line in script.js:
const response = await fetch(`http://localhost:3000/pwned/${prefix}`);

If you are running a local server to check for password breaches via the "Have I Been Pwned" API, leave it as http://localhost:3000/pwned/${prefix}.

If you want to use a deployed backend, replace localhost:3000 with the appropriate URL for your deployed API

To start the backend server, run:
node server.mjs
Open the app in your browser by navigating to http://localhost:3000 or just open index.html directly.

![Alt text](/Screen%20Shot%202024-12-04%20at%2010.00.22%20AM.png)
![Alt text](/Screen%20Shot%202024-12-04%20at%2010.00.32%20AM.png)
![Alt text](/Screen%20Shot%202024-12-04%20at%2010.00.40%20AM.png)
![Alt text](/Screen%20Shot%202024-12-04%20at%209.58.59%20AM.png)
![Alt text](/Screen%20Shot%202024-12-04%20at%209.59.05%20AM.png)
![Alt text](/Screen%20Shot%202024-12-04%20at%209.59.31%20AM.png)



