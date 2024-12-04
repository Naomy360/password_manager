let savedPasswords = [];

// Generate Encryption Key
async function generateKey(masterPassword, salt = "unique_salt") {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(masterPassword + salt),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: new TextEncoder().encode(salt),
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypt Data
async function encryptData(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate IV
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        new TextEncoder().encode(data)
    );
    return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
}

// Decrypt Data
async function decryptData(encryptedData, key, iv) {
    return new TextDecoder().decode(
        await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(iv) },
            key,
            new Uint8Array(encryptedData)
        )
    );
}

// Hash Data
async function hashData(data) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
    return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

// Generate Secure Password
function generateSecurePassword(length, includeUppercase, includeNumbers, includeSpecialChars) {
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const specialChars = "!@#$%^&*()_+[]{}|;:,.<>?";
    let characters = lowercase;

    if (includeUppercase) characters += uppercase;
    if (includeNumbers) characters += numbers;
    if (includeSpecialChars) characters += specialChars;

    let password = "";
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    for (let i = 0; i < length; i++) {
        password += characters[array[i] % characters.length];
    }

    return password;
}

document.addEventListener("DOMContentLoaded", () => {
    // Generate Password
    document.getElementById("generate").addEventListener("click", () => {
        const length = parseInt(document.getElementById("length").value);
        const includeUppercase = document.getElementById("uppercase").checked;
        const includeNumbers = document.getElementById("numbers").checked;
        const includeSpecial = document.getElementById("special").checked;

        if (isNaN(length) || length < 8 || length > 32) {
            alert("Please enter a valid password length between 8 and 32.");
            return;
        }

        const password = generateSecurePassword(length, includeUppercase, includeNumbers, includeSpecial);
        document.getElementById("password").value = password;

        const entropy = calculateEntropy(password);
        const strength = evaluateStrength(entropy);
        document.getElementById("strength-meter").value = strength.value;
        document.getElementById("user-strength-text").textContent = `Password Strength: ${strength.level}`;

        // Clear generated password after 30 seconds
        setTimeout(() => {
            document.getElementById("password").value = "";
            document.getElementById("strength-meter").value = 0;
        }, 30000);
    });

    // Check Password Strength
    document.getElementById("check-strength").addEventListener("click", () => {
        const password = document.getElementById("user-password").value;

        if (!password) {
            alert("Please enter a password to check!");
            return;
        }

        const entropy = calculateEntropy(password);
        const strength = evaluateStrength(entropy);

        document.getElementById("user-strength-meter").value = strength.value;
        document.getElementById("user-strength-text").textContent = `Password Strength: ${strength.level}`;

        // Clear test password after 30 seconds
        setTimeout(() => {
            document.getElementById("user-password").value = "";
            document.getElementById("user-strength-meter").value = 0;
            document.getElementById("user-strength-text").textContent = "Password strength will appear here.";
        }, 30000);
    });

    // Check if Password is Pwned
    document.getElementById("check-breach").addEventListener("click", async () => {
        const password = document.getElementById("user-password").value;

        if (!password) {
            alert("Please enter a password to check!");
            return;
        }

        const breached = await checkPasswordPwned(password);
        if (breached === null) {
            document.getElementById("breach-result").textContent = "Error checking breaches. Please try again.";
        } else if (breached > 0) {
            document.getElementById("breach-result").textContent = `Your password has been exposed in a data breach (${breached} times). Consider changing it.`;
        } else {
            document.getElementById("breach-result").textContent = "Your password is safe.";
        }

        // Clear test password and result after 30 seconds
        setTimeout(() => {
            document.getElementById("user-password").value = "";
            document.getElementById("breach-result").textContent = "";
        }, 30000);
    });

    // Create Password Fields Dynamically
    document.getElementById("create-password-fields").addEventListener("click", () => {
        const numPasswords = parseInt(document.getElementById("number-of-passwords").value);
        const container = document.getElementById("password-fields-container");
        container.innerHTML = ""; // Clear existing fields

        for (let i = 0; i < numPasswords; i++) {
            const labelInput = document.createElement("input");
            labelInput.type = "text";
            labelInput.placeholder = `Account Label ${i + 1}`;
            labelInput.classList.add("account-label");

            const passwordInput = document.createElement("input");
            passwordInput.type = "password";
            passwordInput.placeholder = `Password ${i + 1}`;
            passwordInput.classList.add("account-password");

            container.appendChild(labelInput);
            container.appendChild(passwordInput);
        }

        document.getElementById("encrypt-and-download").style.display = "block"; // Show Encrypt and Download button
    });

    // Encrypt and Download Passwords
    document.getElementById("encrypt-and-download").addEventListener("click", async () => {
        const encryptionKeyInput = document.getElementById("encryption-key").value;
        const confirmKeyInput = document.getElementById("confirm-encryption-key").value;

        if (!encryptionKeyInput || encryptionKeyInput !== confirmKeyInput) {
            alert("Encryption keys do not match or are empty!");
            return;
        }

        const encryptionKey = await generateKey(encryptionKeyInput);
        const labels = document.querySelectorAll(".account-label");
        const passwords = document.querySelectorAll(".account-password");

        const entries = [];
        labels.forEach((label, index) => {
            const labelValue = label.value;
            const passwordValue = passwords[index].value;

            if (labelValue && passwordValue) {
                entries.push({ label: labelValue, password: passwordValue });
            }
        });

        if (entries.length === 0) {
            alert("Please fill in all fields for labels and passwords!");
            return;
        }

        const savedData = [];
        for (const entry of entries) {
            const encrypted = await encryptData(
                JSON.stringify({ label: entry.label, password: entry.password }),
                encryptionKey
            );

            savedData.push({
                label: entry.label,
                iv: encrypted.iv,
                data: encrypted.data,
            });
        }

        const blob = new Blob([JSON.stringify(savedData, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "encrypted-passwords.json";
        a.click();

        alert("Encrypted passwords have been downloaded!");
    });

    // Decrypt File
    document.getElementById("decrypt-file").addEventListener("click", async () => {
        const fileInput = document.getElementById("password-file");
        const file = fileInput.files[0];

        if (!file) {
            alert("Please select a file to decrypt!");
            return;
        }

        const decryptionKeyInput = document.getElementById("decryption-key").value;

        if (!decryptionKeyInput) {
            alert("Please enter the decryption key!");
            return;
        }

        const decryptionKey = await generateKey(decryptionKeyInput);

        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                const encryptedData = JSON.parse(e.target.result);
                const decryptedData = [];

                for (const entry of encryptedData) {
                    const decrypted = await decryptData(entry.data, decryptionKey, entry.iv);
                    decryptedData.push(JSON.parse(decrypted));
                }

                // Display decrypted content
                const decryptedPasswordsList = document.getElementById("decrypted-passwords");
                decryptedPasswordsList.innerHTML = "";
                decryptedData.forEach((item) => {
                    const listItem = document.createElement("li");
                    listItem.textContent = `Label: ${item.label}, Password: ${item.password}`;
                    decryptedPasswordsList.appendChild(listItem);
                });

                // Show decrypted content and download button
                document.getElementById("decrypted-content").style.display = "block";

                // Download decrypted content
                document.getElementById("download-decrypted-file").addEventListener("click", () => {
                    const blob = new Blob([JSON.stringify(decryptedData, null, 2)], { type: "application/json" });
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = "decrypted-passwords.json";
                    a.click();
                });

                alert("Decryption successful! Content displayed and ready for download.");
            } catch (error) {
                console.error("Error decrypting file:", error);
                alert("Decryption failed! Please check the decryption key or file.");
            }
        };

        reader.readAsText(file);
    });
});

// Calculate Password Entropy
function calculateEntropy(password) {
    const charSetSize = new Set(password).size;
    return password.length * Math.log2(charSetSize);
}

// Evaluate Password Strength
function evaluateStrength(entropy) {
    if (entropy < 40) return { level: "Weak", value: 33 };
    if (entropy < 60) return { level: "Moderate", value: 66 };
    return { level: "Strong", value: 100 };
}

// Check if Password is Pwned
async function checkPasswordPwned(password) {
    try {
        // Hash the password using SHA-1
        const hashBuffer = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
        const hashHex = Array.from(new Uint8Array(hashBuffer))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
            .toUpperCase();

        // Extract prefix and suffix for the API call
        const prefix = hashHex.slice(0, 5);
        const suffix = hashHex.slice(5);

        // Fetch breached data from the server
        const response = await fetch(`http://localhost:3000/pwned/${prefix}`);
        if (!response.ok) {
            throw new Error(`Server responded with status ${response.status}: ${response.statusText}`);
        }

        const data = await response.text();
        const lines = data.split("\n");

        // Search for the matching hash suffix
        for (const line of lines) {
            const [lineSuffix, count] = line.split(":");
            if (lineSuffix === suffix) {
                return parseInt(count, 10);
            }
        }

        return 0; // Password not found in breaches
    } catch (error) {
        console.error("Error in checkPasswordPwned:", error.message || error);
        alert("An error occurred while checking for breaches. Please try again.");
        return null; // Indicate failure
    }
}


document.getElementById("encrypt-share").addEventListener("click", async () => {
    try {
        const password = document.getElementById("share-password").value;

        if (!password) {
            alert("Please enter a password to share!");
            return;
        }

        if (!window.keyPair || !window.keyPair.publicKey) {
            alert("Key pair is not generated. Please re-enter your password.");
            return;
        }

        // Encrypt the password
        const encodedPassword = new TextEncoder().encode(password);
        const encryptedPassword = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            window.keyPair.publicKey,
            encodedPassword
        );

        const encryptedPasswordBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedPassword)));

        // Save encrypted password and public key as a file
        const publicKey = await window.crypto.subtle.exportKey("spki", window.keyPair.publicKey);
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKey)));

        const sharedData = {
            encryptedPassword: encryptedPasswordBase64,
            publicKey: publicKeyBase64,
        };

        const blob = new Blob([JSON.stringify(sharedData, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "shared_password.json";
        a.click();

        document.getElementById("share-status").textContent = "Password encrypted and file downloaded!";
    } catch (error) {
        console.error("Error encrypting and sharing password:", error);
        alert("Failed to encrypt and share the password. Please try again.");
    }
});
document.getElementById("generate-keys").addEventListener("click", async () => {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: "SHA-256",
            },
            true, // Can export keys
            ["encrypt", "decrypt"]
        );

        // Export and display the public key
        const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKey)));
        document.getElementById("public-key-display").textContent = `Public Key (share this):\n${publicKeyBase64}`;

        // Store private key for later decryption
        const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const privateKeyBlob = new Blob([privateKey], { type: "application/octet-stream" });
        const privateKeyURL = URL.createObjectURL(privateKeyBlob);
        const privateKeyDownloadLink = document.createElement("a");
        privateKeyDownloadLink.href = privateKeyURL;
        privateKeyDownloadLink.download = "private_key.pem";
        privateKeyDownloadLink.textContent = "Download Your Private Key";
        privateKeyDownloadLink.style.display = "block";

        document.getElementById("share-status").appendChild(privateKeyDownloadLink);

        // Enable Encrypt and Share button
        document.getElementById("encrypt-share").disabled = false;

        // Store the key pair for later use
        window.keyPair = keyPair;
    } catch (error) {
        console.error("Error generating RSA keys:", error);
        alert("Failed to generate keys. Please try again.");
    }
});

    
document.getElementById("decrypt-shared").addEventListener("click", async () => {
    try {
        const sharedFile = document.getElementById("shared-encrypted-password").files[0];
        const privateKeyFile = document.getElementById("private-key-file").files[0];

        if (!sharedFile || !privateKeyFile) {
            alert("Please provide both the shared file and your private key.");
            return;
        }

        // Read the shared file (containing the encrypted password and public key)
        const sharedFileContent = await sharedFile.text();
        const sharedData = JSON.parse(sharedFileContent);
        const encryptedPasswordBase64 = sharedData.encryptedPassword;

        // Read the private key file
        const privateKeyBuffer = await privateKeyFile.arrayBuffer();
        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            privateKeyBuffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );

        // Decode the encrypted password
        const encryptedPassword = Uint8Array.from(atob(encryptedPasswordBase64), (char) => char.charCodeAt(0));

        // Decrypt the password
        const decryptedPasswordBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedPassword
        );

        const decryptedPassword = new TextDecoder().decode(decryptedPasswordBuffer);
        document.getElementById("decrypted-shared-result").textContent = `Decrypted Password: ${decryptedPassword}`;
    } catch (error) {
        console.error("Error decrypting shared password:", error);
        alert("Failed to decrypt the password. Please ensure the files are correct.");
    }
});
