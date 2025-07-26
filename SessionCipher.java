import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {

    private Cipher encryptionCipher;
    private Cipher decryptionCipher;
    private SessionKey sessionKey;
    private byte[] ivbytes;

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) {
        sessionKey = key;

        ivbytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivbytes);

        initCipher();
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) {
        sessionKey = key;
        this.ivbytes = ivbytes;

        initCipher();
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return sessionKey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return ivbytes;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        return new CipherOutputStream(os, encryptionCipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        return new CipherInputStream(inputstream, decryptionCipher);
    }

    private void initCipher(){
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivbytes);

            encryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);

            decryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
            decryptionCipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);

        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
