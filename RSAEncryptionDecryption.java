package com.example.demo;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "http://localhost:3000")
public class RSAEncryptionDecryption {

	@GetMapping("/welcom")
	public String decrypt() throws Exception {
		return "welcome";
	}
	
	@GetMapping("/getKey")
	public ResponseEntity<Object> getPublicKey() throws Exception {
		Map<String, Object> map = new HashMap<>();
		KeyPair keyPair = RSAEncryotionDecryption.generateKeyPair();
		// Get the public and private keys
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("PublicKey");
        System.out.println(publicKey);
        // Print or store the public and private keys as needed
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(publicKeyBytes);
        String privateKeyString = Base64.getEncoder().encodeToString(privateKeyBytes);

        System.out.println("Public Key: " + publicKeyString);
        System.out.println("Private Key: " + privateKeyString);
        map.put("publicKey", publicKeyString);
        map.put("status", true);
        return ResponseEntity.ok(map);
	}
	
	@PostMapping("/decrypt")
	public String decrypt(@RequestParam("message") String message) throws Exception {
		String decrypt = RSAEncryotionDecryption.decrypt(message);
		return decrypt;
	}
}
