// Object to store users' key pairs
const users = {
  user1: {},
  user2: {},
  user3: {},
  user4: {},
  user5: {},
};

// Generates a new RSA key pair for signing and verification
async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: 'SHA-256' },
    },
    true,
    ['sign', 'verify']
  );
  return keyPair;
}

// Immediately generate key pairs for all users
(async function () {
  for (const user in users) {
    users[user].keyPair = await generateKeyPair();
  }
  console.log('Key pairs generated:', users);
})();

// Generates a new AES-GCM key and initialization vector (IV)
async function generateSecretKey() {
  const key = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  return { key, iv };
}

// Encrypts a message using AES-GCM
async function encryptMessage(message, secretKey) {
  const enc = new TextEncoder();
  const encodedMessage = enc.encode(message);

  const encryptedMessage = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: secretKey.iv,
    },
    secretKey.key,
    encodedMessage
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encryptedMessage))),
    iv: btoa(String.fromCharCode(...new Uint8Array(secretKey.iv))),
  };
}

// Decrypts a message using AES-GCM
async function decryptMessage(ciphertext, iv, secretKey) {
  const enc = new TextDecoder();
  const encryptedMessage = new Uint8Array(
    atob(ciphertext)
      .split('')
      .map((char) => char.charCodeAt(0))
  );
  const ivArray = new Uint8Array(
    atob(iv)
      .split('')
      .map((char) => char.charCodeAt(0))
  );

  try {
    const decryptedMessage = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivArray,
      },
      secretKey,
      encryptedMessage
    );

    return enc.decode(decryptedMessage);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw error;
  }
}

// Creates a digital signature for the message using the private key
async function createDigitalSignature(message, privateKey) {
  const enc = new TextEncoder();
  const encodedMessage = enc.encode(message);

  const signature = await window.crypto.subtle.sign(
    {
      name: 'RSA-PSS',
      saltLength: 32,
    },
    privateKey,
    encodedMessage
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// Verifies the digital signature using the public key
async function verifyDigitalSignature(message, signature, publicKey) {
  const enc = new TextEncoder();
  const encodedMessage = enc.encode(message);
  const signatureArray = new Uint8Array(
    atob(signature)
      .split('')
      .map((char) => char.charCodeAt(0))
  );

  try {
    const isValid = await window.crypto.subtle.verify(
      {
        name: 'RSA-PSS',
        saltLength: 32,
      },
      publicKey,
      signatureArray,
      encodedMessage
    );

    return isValid;
  } catch (error) {
    console.error('Signature verification failed:', error);
    throw error;
  }
}

// Event listener for sending an encrypted message
document.getElementById('sendMessageBtn').addEventListener('click', async () => {
  const message = document.getElementById('messageInput').value;
  const recipient = document.getElementById('recipientSelect').value;

  if (message && recipient) {
    try {
      const recipientKeyPair = users[recipient].keyPair;

      const secretKeyObject = await generateSecretKey();

      const { ciphertext: encryptedMessage, iv } = await encryptMessage(message, secretKeyObject);
      const digitalSignature = await createDigitalSignature(encryptedMessage, users['user1'].keyPair.privateKey);

      displaySentMessage(encryptedMessage, recipient, digitalSignature, iv);
    } catch (error) {
      console.error('Error sending encrypted message:', error);
      alert('An error occurred while sending the encrypted message.');
    }
  } else {
    alert('Please enter a message and select a recipient.');
  }
});

// Displays the sent message in the received messages section
function displaySentMessage(encryptedMessage, recipient, digitalSignature, iv) {
  const receivedMessagesDiv = document.getElementById('receivedMessages');

  const messageElement = document.createElement('div');
  messageElement.classList.add('message');
  messageElement.innerHTML = `
        <p><strong>From:</strong> You</p>
        <p><strong>To:</strong> ${recipient}</p>
        <p><strong>Encrypted Message:</strong> ${encryptedMessage}</p>
        <p><strong>Signature:</strong> ${digitalSignature}</p>
        <button data-iv='${iv}' data-signature='${digitalSignature}' onclick="decryptAndVerifyMessage('${encryptedMessage}', '${recipient}')">Decrypt & Verify</button>
    `;

  receivedMessagesDiv.appendChild(messageElement);
}

// Decrypts and verifies a received message
async function decryptAndVerifyMessage(encryptedMessage, recipient) {
  try {
    const iv = event.target.dataset.iv;
    const digitalSignature = event.target.dataset.signature;

    const decryptedMessage = await decryptMessage(encryptedMessage, iv, users[recipient].keyPair.privateKey);
    console.log('Decrypted Message:', decryptedMessage);

    const senderPublicKey = users['user1'].keyPair.publicKey; // Assuming sender is user1
    const isValid = await verifyDigitalSignature(encryptedMessage, digitalSignature, senderPublicKey);
    console.log('Signature Valid:', isValid);

    alert(`Decrypted Message: ${decryptedMessage}\nSignature Valid: ${isValid}`);
  } catch (error) {
    console.error('Error in decryption or verification:', error);
    alert('An error occurred during decryption or signature verification.');
  }
}
