package ai.rnt.ascl.seeds.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.springframework.http.ResponseEntity;

public class RSAEncryptionDecryption {

	private static PrivateKey privateKey = null;
	private static PublicKey publicKey = null;
	private static final String JKS_PASSWORD = "demo@123";
	private static final String JSK_PATH = "C:\\Users\\Rajiv Adhav\\git\\seeds-java-Rajiv\\keystore.jks";
	private static final String PRIVATE_KEY_PEM_PATH = "C:\\Users\\Rajiv Adhav\\git\\seeds-java-Rajiv\\privateKey.pem";
	
	public static KeyPair generateKeyPair() throws Exception {
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	        keyGen.initialize(2048); // Key size
	        KeyPair keyPair = keyGen.generateKeyPair();
	        privateKey = keyPair.getPrivate();
	        publicKey = keyPair.getPublic();
	        savePrivateKeyInFile(keyPair.getPrivate());
	        generateCertificateAndSaveKeys(keyPair);
	        
	       return keyPair;

	}
	
	 private static void generateCertificateAndSaveKeys(KeyPair keyPair) throws Exception {
		// Create a self-signed X.509 certificate
	        X509Certificate cert = generateCertificate(keyPair);

	        // Store the key pair and certificate in a keystore
	        KeyStore keyStore = KeyStore.getInstance("JKS");
	        char[] password = JKS_PASSWORD.toCharArray();
	        keyStore.load(null, password);

	        // Add the private key and certificate entry to the keystore
	        keyStore.setKeyEntry("alias", keyPair.getPrivate(), password, new Certificate[]{cert});

	        // Save the keystore to a file
	        FileOutputStream fos = new FileOutputStream(JSK_PATH);
	        keyStore.store(fos, password);
	        fos.close();
	}

	private static X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
	        // Create a certificate generator
	        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
	        certGen.setSerialNumber(new BigInteger(128, new SecureRandom()));
	        certGen.setSubjectDN(new X509Principal("CN=Test Certificate"));
	        certGen.setIssuerDN(new X509Principal("CN=Test Certificate"));
	        certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
	        certGen.setNotAfter(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000)); // 1 year validity
	        certGen.setPublicKey(keyPair.getPublic());
	        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

	        return certGen.generate(keyPair.getPrivate(), "BC");
	    }
	
	private static void savePrivateKeyInFile(PrivateKey privateKey) throws IOException {
		  try (FileWriter fw = new FileWriter(PRIVATE_KEY_PEM_PATH);
				  BufferedWriter bw = new BufferedWriter(fw)) {
	            bw.write(java.util.Base64.getEncoder().encodeToString(privateKey.getEncoded()));
	        }	
	}
	
	private static PrivateKey getPrivateKeyFromPEMFile(String path) throws NoSuchAlgorithmException, FileNotFoundException, IOException, InvalidKeySpecException {
		StringBuilder content = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                content.append(line);
            }
        }
        
     // Decode Base64 and create PrivateKey object
        byte[] decodedKey = Base64.getDecoder().decode(content.toString());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
	}

	public static String decrypt(String encryptedDataFromReact) throws Exception {

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedDataFromReact);
        //Get private key from Java key store
        PrivateKey privateKey = getKeysFromJKS();

        // Decrypt using private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        String decryptedMessage = new String(decryptedBytes);
        System.out.println("Decrypted: " + decryptedMessage);
        return decryptedMessage;
	}
	
	public static PrivateKey getKeysFromJKS() throws Exception {
		// Load the keystore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		char[] password = JKS_PASSWORD.toCharArray();
		FileInputStream fis = new FileInputStream(JSK_PATH);
		keyStore.load(fis, password);
		fis.close();

		// Get the private key and certificate from the keystore
		String alias = "alias"; 
		// Replace with the alias used while storing the key pair
		Key key = keyStore.getKey(alias, password);
		if (key instanceof PrivateKey) {
			Certificate cert = keyStore.getCertificate(alias);
			PublicKey publicKey = cert.getPublicKey();

			System.out.println("Public Key: " + publicKey);
			System.out.println("Private Key: " + key);
		}
		return (PrivateKey) key;
	}
	
	public static boolean verifySignature(String message, String signature, String publicKey) throws Exception {
		byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		 // Convert byte array to PublicKey object
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey signaturePublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

		// Assuming publicKey contains the RSA public key received from front-end
		Signature verifier = Signature.getInstance("SHA256withRSA");
		verifier.initVerify(signaturePublicKey);
		verifier.update(messageBytes);
		return verifier.verify(signatureBytes); 
	}
	
	public static ResponseEntity<Object> decryptAndSignatureVerification(String message, String signature, String publicKey) {
		Map<String, Object> map = new HashMap<>();
		String errorMessage = null;
		try {
			String decryptedMessage = decrypt(message);
			if(verifySignature(decryptedMessage, signature, publicKey)) {
				map.put("data", decryptedMessage);
				errorMessage = "Signature is verified";
			}else {
				map.put("data", null);
				errorMessage = "Signature is not verified";
			}
		} catch (Exception e) {
			errorMessage = errorMessage+" "+e.getMessage();
		}
		map.put("message", errorMessage);
		return ResponseEntity.ok(map) ;
	}
}
