import { createHash } from 'crypto';
import { DecryptedCertificate } from './decrypt-certificate.js';
import { secp256k1 } from '@noble/curves/secp256k1';

export const validateSignature = (
  certificate: DecryptedCertificate,
  secp256k1PublicKeyHex: string
): boolean => {
  try {
    // Create a hash of the certificate for verification
    const certificateBytes = Buffer.from(
      JSON.stringify({
        principal: certificate.certificate.principal,
        timestamp: certificate.certificate.timestamp,
      })
    );
    const certificateHash = createHash('sha256')
      .update(certificateBytes)
      .digest();

    // Convert the signature from hex to bytes
    const signature = Buffer.from(certificate.issuer_signature, 'hex');

    // Convert the public key from hex to bytes
    const publicKey = Buffer.from(secp256k1PublicKeyHex, 'hex');

    // Verify the signature
    const isValid = secp256k1.verify(signature, certificateHash, publicKey);

    return isValid;
  } catch (error) {
    console.error('Signature validation error:', error);
    return false;
  }
};
