import { createDecipheriv } from 'crypto';

export type DecryptedCertificate = {
  principal_id: string;
  certificate: {
    principal: string;
    timestamp: number;
  };
  issuer_signature: string;
};

export const decryptCertificate = (encryptedHex: string, keyHex: string) => {
  // Clean up the hex string (remove any whitespace or quotes)
  const cleanEncryptedHex = encryptedHex.trim().replace(/['"]/g, '');
  const cleanKeyHex = keyHex.trim().replace(/['"]/g, '');

  // Convert hex strings to buffers
  const encryptedBuffer = Buffer.from(cleanEncryptedHex, 'hex');
  const keyBuffer = Buffer.from(cleanKeyHex, 'hex');

  if (encryptedBuffer.length < 12) {
    throw new Error(
      `Encrypted buffer too short: ${encryptedBuffer.length} bytes`
    );
  }

  // Extract nonce (first 12 bytes) and ciphertext (remaining bytes)
  const nonce = Buffer.from(encryptedBuffer.subarray(0, 12));
  const ciphertext = encryptedBuffer.subarray(12);

  // Create decipher
  const decipher = createDecipheriv('aes-256-gcm', keyBuffer, nonce);

  // Set authentication tag (last 16 bytes of ciphertext)
  const authTag = ciphertext.subarray(ciphertext.length - 16);
  decipher.setAuthTag(authTag);

  // Decrypt (excluding the auth tag)
  const decrypted = Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
    decipher.final(),
  ]);

  // Parse the decrypted JSON
  return JSON.parse(decrypted.toString()) as DecryptedCertificate;
};
