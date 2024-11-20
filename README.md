# Password Manager

This repository contains a **Password Manager** application built using JavaScript and modern cryptographic standards. The application securely stores, retrieves, and manages passwords for different domains. It uses **AES-GCM** for encryption and **PBKDF2** for secure key derivation, ensuring high security for sensitive data.

## Features

- **Secure Password Storage**: Uses AES-GCM encryption with randomly generated Initialization Vectors (IVs).
- **Master Key Derivation**: Employs PBKDF2 with SHA-256 for deriving keys from a master password.
- **Integrity Verification**: Ensures data integrity using HMAC for password verification.
- **Serialization and Restoration**: Allows exporting the password database to a JSON representation and restoring it securely.
- **Password Management**:
  - Add or update passwords for a domain.
  - Retrieve stored passwords.
  - Remove passwords for a domain.
  - Return `null` if a password for a domain doesn’t exist.
- **Cross-Platform Compatibility**: Built with Node.js and Web Crypto APIs.

---

## Installation

1. Clone the repository:
```bash
   git clone https://github.com/<your-repo>/password-manager.git
   cd password-manager
```  
2. Install dependencies:

```bash
npm install
```
3. Run tests to ensure everything works correctly:

```bash
npm test
```
4. Usage
Initialize a Keychain
Create a new keychain with a master password:

```javascript

import Keychain from './pm_main.js';

const masterPassword = 'password123!';
const keychain = await Keychain.init(masterPassword);
```
## Set a Password
Store a password for a domain:

```javascript
await keychain.set('example.com', 'mySecurePassword');
```
## Get a Password
Retrieve the password for a domain:

```javascript
const password = await keychain.get('example.com');
console.log(password); // Outputs: mySecurePassword
```
## Remove a Password
Delete a password for a domain:

```javascript
const success = await keychain.remove('example.com');
console.log(success); // Outputs: true if the domain was removed, false otherwise.
```
## Export and Import Keychain
Dump the keychain to a JSON representation:

```javascript

const data = await keychain.dump();
console.log(data.repr); // Serialized JSON representation
console.log(data.checksum); // Checksum for integrity verification
```
Restore a keychain from a dumped representation:

```javascript
const restoredKeychain = await Keychain.load(
  masterPassword,
  data.repr,
  JSON.parse(data.repr),
  data.checksum
);
```
## Development
**File Structure**
- pm_main.js: Main logic for the password manager.

- lib.js: Helper functions for cryptographic operations and buffer manipulation.

- test/test_password_manager.js: Unit tests for the password manager functionality.

- package.json: Project dependencies and scripts.

## Running Tests
To run the unit tests:

```bash
npm test
```
The test suite covers:

- Keychain initialization
- Password storage and retrieval
- Data integrity checks
- Secure serialization and restoration
## Security Features
- PBKDF2 with Salt: Protects against brute-force attacks by introducing computational complexity.
- AES-GCM Encryption: Ensures confidentiality and integrity of stored passwords.
- HMAC Verification: Protects against tampering by verifying password data integrity.
- Checksum Verification: Prevents unauthorized modification during keychain restoration.

### License
This project is licensed under the Apache License.




## Short Answer Section

**Preventing Information Leakage on Password Lengths**

To prevent the adversary from learning password lengths, we used AES-GCM encryption. The encryption output includes a fixed-size tag and an IV, making it difficult for an adversary to deduce the length of the underlying plaintext.

**Preventing Swap Attacks**

We prevented swap attacks by including the domain name in the data that is encrypted and verifying it after decryption. If entries were swapped, the decrypted domain would not match the expected domain, causing the retrieval to fail. This design ensures that each entry is uniquely bound to its respective domain, making it infeasible for an attacker to rearrange entries without detection.

**Necessity of a Trusted Location for Checksum Storage**

Yes, a trusted location is necessary to securely store the SHA-256 checksum for rollback attack prevention. Without a trusted location, an adversary could replace the stored data and the checksum together, bypassing the rollback protection by reverting both to a previous state. The trusted location ensures the checksum cannot be tampered with, preserving data integrity.

**Using a Randomized MAC Instead of HMAC**

If we used a randomized MAC instead of HMAC, we would no longer be able to reliably use the MAC to look up domain names, as the MAC value would differ each time for the same input. We would need to store additional mappings of each domain to its MAC or perform a sequential scan to find the correct domain, resulting in a performance penalty due to additional storage and lookup costs.

**Reducing Information Leakage on Record Count**

To reduce leakage about the number of records, we could group records into "buckets" and only reveal the number of non-empty buckets, rather than the exact number of records. For instance, if there are 4 to 7 records, we might represent them within one bucket, leaking only that the number is within this range. This approach ensures that an adversary learns only log2(k) about the actual record count.

**Adding Multi-User Support without Compromising Security**

Multi-user support can be added by creating separate keys for shared entries. For example, Alice and Bob could each have individual keys for personal entries, while a shared key (derived from a combined secret or managed through a secure key-sharing protocol) could be used for entries like "nytimes" that both users can access. This ensures that shared entries are accessible without compromising the security of other, individually owned entries.