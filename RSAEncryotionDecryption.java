package com.example.demo;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAEncryotionDecryption {

	private static PrivateKey PRIVATE_KEY = null;
	private static PublicKey PUBLIC_KEY = null;
	
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, IOException {
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	        keyGen.initialize(2048); // Key size
	        KeyPair keyPair = keyGen.generateKeyPair();
	        PRIVATE_KEY = keyPair.getPrivate();
	        PUBLIC_KEY = keyPair.getPublic();
	        savePublicKeyInFile(keyPair.getPublic());
	        
	       return keyPair;

	}
	
	private static void savePublicKeyInFile(PublicKey publicKey) throws IOException {
		String fileName = "C:\\Users\\HP\\Downloads\\demo\\publicKey.pem";
		  try (FileWriter fw = new FileWriter(fileName);
				  BufferedWriter bw = new BufferedWriter(fw)) {
	            bw.write("-----BEGIN PUBLIC KEY-----\n");
	            bw.write(java.util.Base64.getEncoder().encodeToString(publicKey.getEncoded()));
	            bw.write("\n-----END PUBLIC KEY-----\n");
	        }	
	}

	public static String decrypt(String encryptedDataFromReact) throws Exception {

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedDataFromReact);

		/*
		 * KeyFactory keyFactory = KeyFactory.getInstance("RSA"); byte[] privateKeyBytes
		 * = Base64.getDecoder().decode(privateKeyString); PKCS8EncodedKeySpec
		 * privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes); PrivateKey
		 * privateKey = keyFactory.generatePrivate(privateKeySpec);
		 */

        // Decrypt using private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, PRIVATE_KEY);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        String decryptedMessage = new String(decryptedBytes);
        System.out.println("Decrypted: " + decryptedMessage);
        return decryptedMessage;
	}
}
