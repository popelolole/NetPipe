import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;
    private static HandshakeCertificate clientcert;
    private static HandshakeCertificate servercert;
    private static PrivateKey privateKey;
    private static byte[] clientChallengeDigest;
    private static byte[] serverChallengeDigest;
    private static SessionKey sessionKey;
    private static byte[] ivbytes;
    private static CipherInputStream cipherIn;
    private static CipherOutputStream cipherOut;
    private static HandshakeMessage serverHello;
    private static HandshakeMessage clientHello;
    private static HandshakeMessage sessionMessage;
    private static HandshakeCertificate cacert;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<usercertificate>");
        System.err.println(indent + "--key=<privatekey>");
        System.err.println(indent + "--cacert=<CA certificate>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "usercertificate");
        arguments.setArgumentSpec("key", "privatekey");
        arguments.setArgumentSpec("cacert", "CA certificate");

        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }

        if(arguments.get("port") == null || arguments.get("key") == null
                || arguments.get("usercert") == null || arguments.get("cacert") == null)
            usage();
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) {
        parseArgs(args);
        ServerSocket serverSocket = null;

        privateKey = readPrivateKeyFromFile(arguments.get("key"));
        cacert = readCertificateFromFile(arguments.get("cacert"));
        servercert = readCertificateFromFile(arguments.get("usercert"));
        try {
            servercert.verify(cacert);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException |
                 NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        readClientHello(socket);
        serverHello(socket);
        readSessionMessage(socket);
        serverFinished(socket);
        readClientFinished(socket);

        SessionCipher cipher = new SessionCipher(sessionKey, ivbytes);
        try {
            cipherIn = cipher.openDecryptedInputStream(socket.getInputStream());
            cipherOut = cipher.openEncryptedOutputStream(socket.getOutputStream());
            Forwarder.forwardStreams(System.in, System.out, cipherIn, cipherOut, socket);
            cipherIn.close();
            cipherOut.close();
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }

    private static void readClientHello(Socket socket){
        try {
            HandshakeMessage fromClient = HandshakeMessage.recv(socket);
            if(fromClient.getType().equals(HandshakeMessage.MessageType.CLIENTHELLO)) {
                clientHello = fromClient;
                String base64Certificate = fromClient.getParameter("Certificate");
                if(base64Certificate == null){
                    System.out.println("Client Hello Missing Certificate...");
                    System.exit(1);
                }
                byte[] decodedBytes = Base64.getDecoder().decode(base64Certificate);
                clientcert = new HandshakeCertificate(decodedBytes);
                clientcert.verify(cacert);
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | SignatureException |
                 InvalidKeyException | NoSuchProviderException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private static void serverHello(Socket socket){
        try {
            serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
            String base64Cert = Base64.getEncoder().encodeToString(servercert.getBytes());
            serverHello.putParameter("Certificate", base64Cert);
            serverHello.send(socket);
        } catch (IOException e) {
            System.out.println("Error sending server hello");
            System.exit(1);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void readSessionMessage(Socket socket){
        try {
            HandshakeMessage fromClient = HandshakeMessage.recv(socket);
            if(fromClient.getType().equals(HandshakeMessage.MessageType.SESSION)) {
                sessionMessage = fromClient;
                HandshakeCrypto privateKeyCrypto = new HandshakeCrypto(privateKey.getEncoded());
                String base64EncryptedKey = fromClient.getParameter("SessionKey");
                if (base64EncryptedKey == null) {
                    System.out.println("Missing session key");
                    System.exit(1);
                }
                sessionKey = new SessionKey(privateKeyCrypto.decrypt(Base64.getDecoder().decode(base64EncryptedKey)));

                String base64EncryptedIV = fromClient.getParameter("SessionIV");
                if (base64EncryptedIV == null) {
                    System.out.println("Missing Session IV");
                    System.exit(1);
                }
                ivbytes = privateKeyCrypto.decrypt(Base64.getDecoder().decode(base64EncryptedIV));
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private static void serverFinished(Socket socket){
        try {
            HandshakeMessage message = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
            HandshakeDigest digest = new HandshakeDigest();
            digest.update(serverHello.getBytes());
            byte[] messageDigest = digest.digest();
            HandshakeCrypto crypto = new HandshakeCrypto(privateKey.getEncoded());
            String base64SignedMessage = Base64.getEncoder().encodeToString(
                    crypto.encrypt(messageDigest));
            message.putParameter("Signature", base64SignedMessage);
            byte[] timestamp = getUTF8TimeStamp();
            String base64SignedTimeStamp = Base64.getEncoder().encodeToString(
                    crypto.encrypt(timestamp));
            message.putParameter("TimeStamp", base64SignedTimeStamp);
            message.send(socket);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static void readClientFinished(Socket socket){
        try {
            HandshakeMessage fromClient = HandshakeMessage.recv(socket);
            if(fromClient.getType().equals(HandshakeMessage.MessageType.CLIENTFINISHED)) {
                HandshakeCrypto crypto = new HandshakeCrypto(clientcert);

                String signature = fromClient.getParameter("Signature");
                if (signature == null) {
                    System.out.println("Signature missing");
                    System.exit(1);
                }
                HandshakeDigest digest = new HandshakeDigest();
                digest.update(clientHello.getBytes());
                digest.update(sessionMessage.getBytes());
                if(!Arrays.equals(digest.digest(), crypto.decrypt(Base64.getDecoder().decode(signature)))){
                    System.out.println("Invalid Signature");
                    System.exit(1);
                }

                String timestamp = fromClient.getParameter("TimeStamp");
                if (timestamp == null) {
                    System.out.println("Timestamp missing");
                    System.exit(1);
                }
                byte[] clientTimeStamp = crypto.decrypt(Base64.getDecoder().decode(timestamp));
                long clientTime = parseTimeStamp(clientTimeStamp);
                long serverTime = parseTimeStamp(getUTF8TimeStamp());
                if(Math.abs(serverTime - clientTime) > 5000){
                    System.out.println("Invalid Client Timestamp");
                    System.exit(1);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private static HandshakeCertificate readCertificateFromFile(String filepath) {
        try (InputStream inStream = new FileInputStream(filepath)) {
            return new HandshakeCertificate(inStream);
        } catch (FileNotFoundException e) {
            System.out.println("Certificate file not found");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("Error reading certificate from file");
            System.exit(1);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    private static PrivateKey readPrivateKeyFromFile(String arg){
        try(InputStream inStream = new FileInputStream(arg)){
            byte[] keyBytes = inStream.readAllBytes();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] getUTF8TimeStamp(){
        LocalDateTime now = LocalDateTime.now();

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = now.format(formatter);

        return formattedDateTime.getBytes(StandardCharsets.UTF_8);
    }

    private static long parseTimeStamp(byte[] utf8Timestamp){
        String timestamp = new String(utf8Timestamp, StandardCharsets.UTF_8);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime time = LocalDateTime.parse(timestamp, formatter);
        return time.toEpochSecond(ZoneOffset.UTC);
    }
}
