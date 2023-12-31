import logo from './logo.svg';
import './App.css';
import {useState} from 'react';
import axios from 'axios';


function App() {
  const [inputText, setInputText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');

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

      // Send base64Encrypted to Java backend for decryption
      // Example: sendToJavaBackend(base64Encrypted);
      const formData = new FormData();
      formData.append('message', base64Encrypted);

      const url = 'http://localhost:8080/decrypt'; // Replace with your API endpoint

      const result = await axios.post(url, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      console.log("Decrypted Response");
      console.log(result.data);
  
    } catch (error) {
      console.error('Encryption error:', error);
      throw error;
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const response = await fetch("http://localhost:8080/getKey");
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
