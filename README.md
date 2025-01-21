# **Advanced Multi-Layer Encryptor**

An advanced, multi-layer encryptor designed for maximum security by combining XOR, AES, HMAC, and PBKDF2. This encryptor ensures data integrity, confidentiality, and resistance against common cryptographic attacks.

## **Features**
- 🔒 **Multi-layer encryption**:
  - **XOR Encryption**: Adds an extra layer of obfuscation.
  - **AES Encryption**: Industry-standard symmetric encryption with a 256-bit key.
  - **HMAC Verification**: Ensures data authenticity and integrity.
  - **PBKDF2 Key Derivation**: Protects against brute-force attacks using a secure salt-based key generation.
- 🛡️ **Salted encryption**: Each encryption generates a unique salt for better security.
- ✅ **Integrity protection**: Validates encrypted data with HMAC.
- 🎲 **Randomized Initialization Vectors (IVs)**: Ensures unique encryption for each operation.

## **How It Works**
1. **Key Derivation**:
   - A password is processed with a randomly generated salt using PBKDF2 to produce a 256-bit cryptographic key.
2. **Encryption Process**:
   - The plaintext is first encrypted with XOR using a derived key.
   - The resulting data is further encrypted with AES.
   - An HMAC is calculated on the AES-encrypted data to verify its integrity.
3. **Decryption Process**:
   - Splits the encrypted data into salt, AES-encrypted payload, and HMAC.
   - Verifies the HMAC to ensure data integrity.
   - Decrypts the AES payload, followed by XOR decryption, to recover the original plaintext.

## **Usage**
### Encryption Example
```csharp
string plaintext = "Sensitive Data";
string password = "SecurePassword123";

string encrypted = EncryptComplex(plaintext, password);
Console.WriteLine("Encrypted: " + encrypted);```

### Decryption Example
```csharp
string decrypted = DecryptComplex(encrypted, password);
Console.WriteLine("Decrypted: " + decrypted);
