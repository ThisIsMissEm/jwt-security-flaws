const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const example_payload = {
  sub: "alice",
  iss: "https://openid.c2id.com",
  aud: "client-12345",
  nonce: "n-0S6_WzA2Mj",
  auth_time: 1311280969,
  acr: "c2id.loa.hisec",
};

const example_passphrase = "top secret";

crypto.generateKeyPair(
  "rsa",
  {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: example_passphrase,
    },
  },
  (err, publicKey, privateKey) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }

    const example_secret = {
      key: privateKey,
      passphrase: example_passphrase,
    };

    const expiresIn = 3 * 60 * 1000;

    console.log({ publicKey, privateKey });

    const signed = jwt.sign(example_payload, example_secret, {
      algorithm: "RS512",
      expiresIn,
    });

    let malicious = jwt.sign(example_payload, "", {
      algorithm: "none",
      expiresIn,
      keyid: "test",
    });

    console.log("");
    console.log({ signed, malicious });
    console.log("");

    const tests = { signed, malicious };

    // Test 1: decode with key from creation:
    Object.keys(tests).forEach((testId) => {
      const token = tests[testId];
      const decoded = jwt.decode(token, { complete: true });

      try {
        jwt.verify(token, decoded.header.alg === "none" ? "" : publicKey);
        log("PASS", testId, "decode with key from creation");
      } catch (err) {
        log("FAIL", testId, "decode with key from creation");
      }
    });

    // Test 2: decode with public key
    Object.keys(tests).forEach((testId) => {
      const token = tests[testId];

      try {
        jwt.verify(token, publicKey);
        log("PASS", testId, "decode with public key");
      } catch (err) {
        log("FAIL", testId, "decode with public key");
      }
    });
  }
);

function log(result, testId, message) {
  console.log(`${result}: ${testId.padStart(10)}: ${message}`);
}
