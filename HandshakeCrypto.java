import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
	PublicKey publicKey;
	PrivateKey privateKey;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		publicKey = handshakeCertificate.getCertificate().getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		privateKey = keyFactory.generatePrivate(keySpec);
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			if(privateKey != null){
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
			}
			else{
				cipher.init(Cipher.DECRYPT_MODE, publicKey);
			}
			return cipher.doFinal(ciphertext);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
			throw new RuntimeException(e);
		}
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte[] encrypt(byte[] plaintext) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			if(privateKey != null){
				cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			}
			else{
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			}
			return cipher.doFinal(plaintext);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
			throw new RuntimeException(e);
		}
    }
}
