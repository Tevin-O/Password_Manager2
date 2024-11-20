"use strict";

// Import necessary cryptographic functions and utilities
import { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } from "./lib.js";    // Functions defined in lib.js
import { webcrypto } from 'crypto';
const { subtle } = webcrypto;

// Constants for cryptographic operations
const PBKDF2_ITERATIONS = 100000; // Number of iterations for PBKDF2
const SALT_LENGTH = 16;           // Length of the salt for key derivation
const AES_GCM_IV_LENGTH = 12;     // Length of the IV for AES-GCM

// Main Keychain class for the password manager
export class Keychain {
  constructor() {
    this.kvs = {}; // Key Value Store for hashed domain-password pairs
    this.masterKey = null; // Derived key from the master password
    this.salt = null; // Salt for PBKDF2

    // Bind methods to avoid context issues
    this.set = this.set.bind(this);
    this.get = this.get.bind(this);
    this.remove = this.remove.bind(this);
    this.computeHMAC = this.computeHMAC.bind(this);
    this.hashDomain = this.hashDomain.bind(this);
  }

  // Helper function to derive a key from the master password
  async deriveKey(password, salt) {
    const keyMaterial = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );

    this.masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    if (!this.masterKey) {
      throw new Error("Failed to derive a valid master key.");
    }
  }

  // Helper function to hash domain names
  async hashDomain(domain) {
    const encodedDomain = stringToBuffer(domain);
    const hashBuffer = await subtle.digest("SHA-256", encodedDomain);
    return encodeBuffer(hashBuffer); // Return Base64-encoded hash
  }

  // Initialize the password manager with a master password
  static async init(password) {
    const keychain = new Keychain();
    keychain.salt = getRandomBytes(SALT_LENGTH); // Generate a random salt
    await keychain.deriveKey(password, keychain.salt); // Derive the master key
    return keychain;
  }

  // Load the password manager state from a serialized representation
  static async load(password, representation, parsedContents, trustedDataCheck) {
    if (!representation) throw new Error("Invalid representation: Data is undefined");

    const keychain = new Keychain();
    const { kvs, salt } = JSON.parse(representation); // Deserialize the KVS and salt
    keychain.salt = decodeBuffer(salt); // Store the salt
    await keychain.deriveKey(password, keychain.salt);

    // Verify integrity with SHA-256
    const computedChecksum = await keychain.computeChecksum(representation);
    if (trustedDataCheck && computedChecksum !== trustedDataCheck) {
      throw new Error("Integrity check failed!");
    }

    keychain.kvs = kvs; // Load the KVS
    return keychain;
  }

  // Compute SHA-256 checksum for integrity verification
  async computeChecksum(data) {
    const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(data));
    return bufferToString(hashBuffer);
  }

  // Serialize the current state of the password manager
  async dump() {
    const representation = JSON.stringify({
      kvs: this.kvs,
      salt: encodeBuffer(this.salt),
    });
    const checksum = await this.computeChecksum(representation);
    return { repr: representation, checksum: checksum }; // Returns serialized data and checksum
  }

  // Compute HMAC for data integrity verification
  async computeHMAC(data) {
    if (!this.masterKey) {
      throw new Error("Master Key not initialized!");
    }

    const encoder = new TextEncoder();
    const key = await subtle.importKey(
      "raw",
      await subtle.exportKey("raw", this.masterKey),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await subtle.sign("HMAC", key, encoder.encode(data));
    return bufferToString(signature);
  }

  // Fetch the password for a given domain from the KVS
  async get(name) {
    const hashedName = await this.hashDomain(name); // Hash the domain
    const entry = this.kvs[hashedName];
    if (!entry) return null;

    const { encryptedData, hmac } = entry;
    if (!encryptedData) return null;

    const decryptedData = await this.decrypt(encryptedData);

    // Verify HMAC
    const computedHMAC = await this.computeHMAC(decryptedData);
    if (computedHMAC !== hmac) {
      throw new Error("HMAC verification failed!");
    }

    return decryptedData;
  }

  // Insert or update the password for a given domain
  async set(name, value) {
    const hashedName = await this.hashDomain(name); // Hash the domain
    const encryptedData = await this.encrypt(value);
    const hmac = await this.computeHMAC(value);
    this.kvs[hashedName] = { encryptedData, hmac };
  }

  // Remove the password entry for a specified domain
  async remove(name) {
    const hashedName = await this.hashDomain(name); // Hash the domain
    if (this.kvs[hashedName]) {
      delete this.kvs[hashedName];
      return true;
    } else {
      return false;
    }
  }

  // Encrypt the password using AES-GCM
  async encrypt(password) {
    const iv = getRandomBytes(AES_GCM_IV_LENGTH); // Generate random IV
    const encryptedBuffer = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      this.masterKey,
      stringToBuffer(password)
    );
    return { iv: encodeBuffer(iv), data: encodeBuffer(encryptedBuffer) }; // Return IV and encrypted data
  }

  // Decrypt the password using AES-GCM
  async decrypt(encryptedData) {
    const iv = decodeBuffer(encryptedData.iv);
    const data = decodeBuffer(encryptedData.data);
    const decryptedBuffer = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      this.masterKey,
      data
    );
    return bufferToString(decryptedBuffer); // Return decrypted password
  }
}

// Export the Keychain class for use in other modules
export default Keychain;
