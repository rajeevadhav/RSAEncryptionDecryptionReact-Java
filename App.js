import logo from './logo.svg';
import './App.css';
import {useState} from 'react';
import axios from 'axios';
import CryptoJS from 'crypto-js';


function App() {
  const username = "abc";
  const userPassword = "abc";
  const md5Key = "d3HdLfm2";
  const dummyPassword = "Dummy@123";

  const md5Hashing = (key, userName, password) => {
    return CryptoJS.MD5(CryptoJS.MD5(userName+"#"+password)+"#"+key);
  };

  const sha512Hashing = (key, userName, password) => {
    return CryptoJS.SHA512(CryptoJS.SHA512(userName+"#"+password)+"#"+key);
  };
  
  const password = md5Hashing (md5Key, username, userPassword);
  const shapassword = sha512Hashing (md5Key, username, userPassword);
  const password0 = sha512Hashing (md5Key, username, dummyPassword);
  const password1 = sha512Hashing (md5Key, username, dummyPassword);
 
  console.log("shapassword = ", shapassword.toString());
  console.log("password0 = ", password0.toString());
  console.log("password = ", password.toString());
  console.log("password1 = ", password1.toString());

  const [inputText, setInputText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');

  const callAPiTODecrypt = async (encryptedMessage, signature, publicKey) => {
      // Send base64Encrypted to Java backend for decryption
      const formData = new FormData();
      formData.append('message', encryptedMessage);
      formData.append('signature', signature);
      formData.append('publicKey', publicKey);

      const url = 'http://localhost:8080/seeds/login/decrypt'; 

      const result = await axios.post(url, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      console.log("Decrypted Response");
      console.log(result.data);
  };

  const encryptData = async (data, publicKey) => {
    try {
      // Convert the base64 encoded key string to a Uint8Array
      const binaryKey = Uint8Array.from(atob(publicKey), c => c.charCodeAt(0));

      const publicKeyObj = await window.crypto.subtle.importKey(
        'spki',
        binaryKey,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt']
      );
  
      // Encode the data to be encrypted
      const encodedData = new TextEncoder().encode(data);
  
      // Encrypt the data using the public key
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKeyObj,
        encodedData
      );
      
      // Convert the encrypted data to base64 for transmission
      const encryptedArray = Array.from(new Uint8Array(encrypted));
      const base64Encrypted = btoa(String.fromCharCode(...encryptedArray));
  
      console.log("Encrypted data",base64Encrypted);

      //--------------------Code to create signature---------------------------------------------
          // Generate RSA key pair in React
          console.log("creating keys");
          const keyPair = await crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: { name: "SHA-256" },
            },
            true,
            ["sign", "verify"]
        );
        console.log("keys created");
        // Get the public key for transmission to the Java backend
        const exportedPublicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
        console.log("Signature public key", publicKeyBase64);
         // Sign the data with the private key
         const testData = new TextEncoder().encode("test");
          const signature = await crypto.subtle.sign(
            {
                name: "RSASSA-PKCS1-v1_5",
            },
            keyPair.privateKey,
            testData
           );
           // Convert the signature to Base64 for transmission
         const base64Signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
        console.log("Signature", base64Signature);

         // Sending data to backend
        callAPiTODecrypt(base64Encrypted, base64Signature, publicKeyBase64);
     
    } catch (error) {
      console.error('Encryption error:', error);
      throw error;
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const response = await fetch("http://localhost:8080/seeds/login/getKey");
        if (!response.ok) {
          throw new Error('Network response was not ok.');
        }
        const data = await response.json();
        console.log("public key",data.publicKey);
        const publicKey = data.publicKey;
       encryptData(inputText, publicKey);
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
        />
        <button type="submit">Encrypt</button>
      </form>
      <div>
        <h3>Encrypted Text:</h3>
        <p>{encryptedText}</p>
      </div>
    </div>
  );
}

export default App;
