import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    private MessageDigest messageDigest;

    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() {
        try{
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        messageDigest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return messageDigest.digest();
    }
};
