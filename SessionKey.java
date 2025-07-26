import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/*
 * Skeleton code for class SessionKey
 */
class SessionKey {

    private SecretKey secretKey;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(length);
            secretKey = keyGenerator.generateKey();
        }
        catch(NoSuchAlgorithmException e) {
            System.err.println("Algorithm not found");
        }
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keyBytes) {
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException("Invalid key length. Must be 16, 24, or 32 bytes.");
        }
        secretKey = new SecretKeySpec(keyBytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return secretKey.getEncoded();
    }
}

