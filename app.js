const cookieParser = require("cookie-parser");
const express = require("express");
const expressLayouts = require("express-ejs-layouts");
const bodyParser = require("body-parser");
const app = express();
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const { spawn } = require("child_process");
const { exec } = require("child_process");
var sqlite3 = require("sqlite3");
var db;
app.use(cookieParser());

const port = 6789;
// directorul 'public' va conține toate resursele accesibile direct de către cliente.g., fișiere css, javascript, imagini)
// app.use(express.static(__dirname + 'public'))
app.use(express.static(path.join(__dirname, "public")));
// corpul mesajului poate fi interpretat ca json; datele de la formular se găsesc în format json în req.body
app.use(bodyParser.json());
// utilizarea unui algoritm de deep parsing care suportă obiecte în obiecte
app.use(bodyParser.urlencoded({ extended: true }));
// la accesarea din browser adresei http://localhost:6789/ se va returna textul 'HelloWorld'
// proprietățile obiectului Request - req - https://expressjs.com/en/api.html#req
// proprietățile obiectului Response - res - https://expressjs.com/en/api.html#res
// directorul 'views' va conține fișierele .ejs (html + js executat la server)
app.set("view engine", "ejs");
// suport pentru layout-uri - implicit fișierul care reprezintă template-ul site-uluieste views/layout.ejs
app.use(expressLayouts);

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048, // Recommended key length
  publicKeyEncoding: {
    type: "spki", // Change from "pkcs1" to "spki"
    format: "pem", // PEM format
  },
  privateKeyEncoding: {
    type: "pkcs8", // PKCS#8 for the private key
    format: "pem",
  },
});

const accessAttempts = new Map();
const maxAccessAttempts = 1;
const durationBlocked = 10 * 1000;

app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use((req, res, next) => {
  //Spam protection
  const internetprotol = req.ip;

  if (
    accessAttempts.has(internetprotol) &&
    accessAttempts.get(internetprotol) >= 5
  ) {
    const timeBlocked = accessAttempts.get(internetprotol + "-blockTime");
    if (timeBlocked && Date.now() < timeBlocked + durationBlocked) {
      return res.status(403).send("Access temporarely blocked.");
    } else {
      accessAttempts.delete(internetprotol);
      accessAttempts.delete(internetprotol + "-blockTime");
    }
  }

  // Initialize session variables

  if (!req.session.sequenceNumber) {
    req.session.sequenceNumber = 0; // Start sequence at 0
  }
  if (!req.session.aesKey) {
    req.session.aesKey = null; // AES key to be set during key exchange
  }

  res.locals.username = req.cookies.username;
  res.locals.session = req.session;
  if (req.session.aesKey == null) {
    res.locals.layout = "improvised_handshake";
  } else {
    res.locals.layout = "layout";
  }

  next();
});
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
// Middleware to encrypt all responses
app.use((req, res, next) => {
  if (!req.session.aesKey) {
    console.log("AES key is not set. Skipping encryption.");
    return next(); // Skip encryption and continue to the next middleware/route
  }

  const originalSend = res.send;

  res.send = async function (data) {
    try {
      // Prevent recursive encryption
      if (res.locals.isEncrypted) {
        return originalSend.call(this, data);
      }
      await console.log("Original response data:", data);
      const aesKey = Buffer.from(req.session.aesKey, "hex");
      await console.log(aesKey);

      const sequenceNumber = ++req.session.sequenceNumber || 1; // Increment or initialize
      const iv = generateIV(sequenceNumber);

      // Additional authenticated data
      const aad = ""; // Use actual AAD if needed
      // Encrypt data
      const { encryptedmsg, authTagCpp } = await encryptAESWithCPP(
        data,
        aesKey,
        aad,
        iv
      );

      // Convert data to Base64
      const encryptedDataBase64 = Buffer.from(encryptedmsg).toString("base64");
      const authTagBase64 = Buffer.from(authTagCpp, "utf-8").toString("base64");
      const aadBase64 = Buffer.from(aad).toString("base64");
      const ivHex = iv.toString("hex");

      // Mark the response as encrypted
      res.locals.isEncrypted = true;

      // Send encrypted response
      originalSend.call(this, {
        encryptedData: encryptedDataBase64,
        authTag: authTagBase64,
        aad: aadBase64,
        iv: ivHex,
      });
    } catch (err) {
      console.error("Response encryption failed:", err);
      res.status(500).send("Response encryption failed");
    }
  };

  next();
});
// app.use(async (req, res, next) => {
//   if (!req.session.aesKey) {
//     console.log("AES key is not set. Skipping decryption.");
//     return next(); // Skip encryption and continue to the next middleware/route
//   }
//   // Skip decryption if there's nothing to decrypt
//   if (
//     !req.body ||
//     !req.body.encryptedData ||
//     !req.body.authTag ||
//     !req.body.iv
//   ) {
//     console.log("No encrypted data found in the request. Skipping decryption.");
//     return next();
//   }
//   try {
//     const aesKey = Buffer.from(req.session.aesKey, "hex");

//     const { encryptedData, authTag, aad, iv } = req.body;

//     // Convert from Base64 to Buffers
//     const encryptedDataBuffer = Buffer.from(encryptedData, "base64");
//     const authTagBuffer = Buffer.from(authTag, "base64");
//     const aadBuffer = Buffer.from(aad, "base64");
//     const ivBuffer = Buffer.from(iv, "hex");

//     // Decrypt data
//     const rawData = await decryptAESWithCPP(
//       encryptedDataBuffer,
//       aesKey,
//       aadBuffer,
//       ivBuffer,
//       authTagBuffer
//     );

//     // Replace body with decrypted data
//     req.body = JSON.parse(rawData.toString("utf-8")); // Assuming JSON data

//     next();
//   } catch (err) {
//     console.error("Request decryption failed:", err);
//     res.status(400).send("Request decryption failed");
//   }
// });

// Endpoint to send public key to the client
app.get("/public-key", (req, res) => {
  res.json({ publicKey });
});

// Endpoint to receive encrypted AES key from the client
app.post("/exchange-key", (req, res) => {
  const encryptedAESKey = Buffer.from(req.body.encryptedKey, "base64");
  const decryptedAESKey = crypto.privateDecrypt(
    {
      key: privateKey, // Ensure this is the correct PKCS#8 private key
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Use OAEP padding
      oaepHash: "sha256", // Match the hash algorithm used during encryption
    },
    encryptedAESKey
  );
  req.session.aesKey = decryptedAESKey.toString("hex"); // Store securely in session
  res.sendStatus(200);
});

// Function to call the C++ encryption program
function encryptAESWithCPP(data, key, aad, iv) {
  return new Promise((resolve, reject) => {
    // Convert inputs to Base64
    const dataBase64 = Buffer.from(data).toString("base64");

    const keyBase64 = Buffer.from(
      Buffer.from(key).toString("hex"),
      "utf-8"
    ).toString("base64");

    const aadBase64 = Buffer.from(aad).toString("base64");

    const ivHex = Buffer.from(iv);

    const ivBase64 = Buffer.from(ivHex, "hex").toString("base64");

    // Execute the C++ program with parameters
    const cppProcess = spawn("./criptarebase64aesgcm.exe");

    let encryptedOutput = "";
    let errorOutput = "";

    // Capture the program's output
    cppProcess.stdout.on("data", (chunk) => {
      encryptedOutput += chunk.toString();
    });

    // Capture error output
    cppProcess.stderr.on("data", (chunk) => {
      errorOutput += chunk.toString();
    });

    // Handle process completion
    cppProcess.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(
            `Encryption program exited with code ${code}: ${errorOutput}`
          )
        );
      } else {
        // If the C++ program ran successfully, parse the output
        let timeTakenSecond = 0;
        let authTagCpp = "";
        let encryptedmsg = "";

        // Match for encryption time
        const timeMatch = encryptedOutput.match(
          /Encryption time: (\d+\.\d+) ms/
        );
        if (timeMatch && timeMatch[1]) {
          timeTakenSecond = parseFloat(timeMatch[1]);
        }

        // Match for authentication tag
        const tagMatch = encryptedOutput.match(
          /Tag from the c\+\+ program: (.+)/
        );
        if (tagMatch && tagMatch[1]) {
          authTagCpp = tagMatch[1].trim();
        }

        // Match for encrypted message
        const enctextmatch = encryptedOutput.match(
          /C:\s([\s\S]*?)\nTag from the c\+\+ program:/
        );
        if (enctextmatch && enctextmatch[1]) {
          // Remove any unnecessary whitespace and concatenate lines
          const hexString = enctextmatch[1].replace(/\s+/g, "");
          // Convert the hex string to a Buffer
          encryptedmsg = Buffer.from(hexString, "hex");
        }

        // Resolve with the parsed values
        resolve({
          encryptedmsg, // Encrypted message as a Buffer
          authTagCpp, // Authentication tag
          timeTakenSecond, // Encryption time in milliseconds
        });
      }
    });

    // Handle errors
    cppProcess.on("error", (err) => {
      reject(err);
    });

    // Write input to stdin of the C++ process
    cppProcess.stdin.write(dataBase64 + "\n");
    cppProcess.stdin.write(keyBase64 + "\n");
    cppProcess.stdin.write(aadBase64 + "\n");
    cppProcess.stdin.write(ivBase64 + "\n");
    cppProcess.stdin.end();
  });
}
// Function to call the C++ encryption program
function decryptAESWithCPP(data, key, aad, iv, tag) {
  return new Promise((resolve, reject) => {
    // Convert inputs to Base64
    const dataBase64 = Buffer.from(data).toString("base64");

    const keyBase64 = Buffer.from(
      Buffer.from(key).toString("hex"),
      "utf-8"
    ).toString("base64");

    const aadBase64 = Buffer.from(aad).toString("base64");

    const ivHex = Buffer.from(iv);

    const ivBase64 = Buffer.from(ivHex, "hex").toString("base64");
    const tagBase64 = Buffer.from(tag).toString("base64");
    // Execute the C++ program with parameters
    const cppProcess = spawn("./DEcriptarebase64aesgcm.exe");

    let encryptedOutput = "";
    let errorOutput = "";

    // Capture the program's output
    cppProcess.stdout.on("data", (chunk) => {
      encryptedOutput += chunk.toString();
    });

    // Capture error output
    cppProcess.stderr.on("data", (chunk) => {
      errorOutput += chunk.toString();
    });

    // Handle process completion
    cppProcess.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(
            `Encryption program exited with code ${code}: ${errorOutput}`
          )
        );
      } else {
        // If the C++ program ran successfully, parse the output
        let timeTakenSecond = 0;
        let authTagCpp = "";
        let encryptedmsg = "";

        // Match for encryption time
        const timeMatch = encryptedOutput.match(
          /Encryption time: (\d+\.\d+) ms/
        );
        if (timeMatch && timeMatch[1]) {
          timeTakenSecond = parseFloat(timeMatch[1]);
        }

        // Match for authentication tag
        const tagMatch = encryptedOutput.match(
          /Tag from the c\+\+ program: (.+)/
        );
        if (tagMatch && tagMatch[1]) {
          authTagCpp = tagMatch[1].trim();
        }

        // Match for encrypted message
        const enctextmatch = encryptedOutput.match(
          /C:\s([\s\S]*?)\nTag from the c\+\+ program:/
        );
        if (enctextmatch && enctextmatch[1]) {
          // Remove any unnecessary whitespace and concatenate lines
          const hexString = enctextmatch[1].replace(/\s+/g, "");
          // Convert the hex string to a Buffer
          encryptedmsg = Buffer.from(hexString, "hex");
        }

        // Resolve with the parsed values
        resolve({
          encryptedmsg, // Encrypted message as a Buffer
          authTagCpp, // Authentication tag
          timeTakenSecond, // Encryption time in milliseconds
        });
      }
    });

    // Handle errors
    cppProcess.on("error", (err) => {
      reject(err);
    });

    // Write input to stdin of the C++ process
    cppProcess.stdin.write(dataBase64 + "\n");
    cppProcess.stdin.write(keyBase64 + "\n");
    cppProcess.stdin.write(aadBase64 + "\n");
    cppProcess.stdin.write(tagBase64 + "\n");
    cppProcess.stdin.write(ivBase64 + "\n");
    cppProcess.stdin.end();
  });
}

app.get("/demo", async (req, res) => {
  try {
    // Assuming that encryption is handled by middleware already
    res.render("demo_page"); // Render the demo-page view without manually encrypting the content
  } catch (err) {
    console.error("Error rendering demo page:", err);
    res.status(500).send("Error rendering demo page");
  }
});

function generateIV(sequenceNumber) {
  // Allocate a 12-byte buffer
  const ivBuffer = Buffer.alloc(12);
  // Write the sequence number into the last 4 bytes
  ivBuffer.writeUInt32BE(sequenceNumber, 8); // Position it at offset 8
  return ivBuffer.toString("hex");
}

app.get("/", (req, res) => {
  const admin = req.cookies.admin === "true";
  db = new sqlite3.Database("cumparaturi.db", sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
      console.error(err);
      res.render("index", { products: [], authenticated: false, admin: admin });
      return;
    }

    db.serialize(() => {
      const username = req.cookies.username;
      const authenticated = username ? true : false;

      db.get(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='produse'",
        (err, table) => {
          if (err) throw err;

          if (table) {
            db.all("SELECT * FROM produse", (err, rows) => {
              if (err) throw err;
              res.render("demo_page", {
                products: rows,
                authenticated: authenticated,
                admin: admin,
                username: username,
              });
            });
          } else {
            res.render("demo_page", {
              products: [],
              authenticated: authenticated,
              admin: admin,
              username: username,
            });
          }
        }
      );
    });
  });
});
app.get("/encryption-stats", (req, res) => {
  const username = req.cookies.username;
  if (!username) {
    res
      .status(401)
      .send("You must be logged in to view encryption statistics.");
    return;
  }

  const query = `
    SELECT first_encryption_time, second_encryption_time, timestamp, name 
    FROM encryption 
    WHERE username = ? 
    ORDER BY timestamp DESC`;

  const createTableQuery = `
     CREATE TABLE IF NOT EXISTS encryption (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       username TEXT,
       first_encryption_time REAL,
       second_encryption_time REAL,
       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
       name TEXT
     )
   `;

  db.run(createTableQuery, (err) => {
    if (err) {
      console.error("Error creating the encryption table:", err);
      res.status(500).send("Error creating the encryption table.");
      return;
    }
    db.all(query, [username], (err, rows) => {
      if (err) {
        console.error("Error querying the database:", err);
        res.status(500).send("Error fetching encryption statistics");
        return;
      }

      res.json(rows);
    });
  });
});
app.post("/upload-encrypt", upload.single("file"), (req, res) => {
  const file = req.file;

  if (!file) {
    res.status(400).send("File is missing");
    return;
  }

  const username = req.cookies.username;
  if (!username) {
    res.status(401).send("You must be logged in to perform this action.");
    return;
  }

  const key = Buffer.from("feffe9928665731c6d6a8f9467308308", "hex");
  const iv = Buffer.alloc(12, 0);
  const aed = Buffer.from("", "utf-8");

  const handleEncryption = (file, filename) => {
    // First Encryption: AES-GCM in Node.js
    const startFirstEncryption = process.hrtime();
    // Check if the Base64 encoded data exceeds the size limit

    const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);

    let encrypted = cipher.update(file, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");
    const endFirstEncryption = process.hrtime(startFirstEncryption);
    const timeTakenFirst =
      (endFirstEncryption[0] * 1e9 + endFirstEncryption[1]) / 1e6; // time in milliseconds

    console.log("First Encryption Auth Tag:", authTag);
    console.log(`First Encryption Time taken: ${timeTakenFirst} ms`);

    // Convert the hex string to a Buffer
    const keyBuffer = Buffer.from("feffe9928665731c6d6a8f9467308308", "utf-8");

    // Encode the Buffer to a Base64 string

    const keyBase64 = keyBuffer.toString("base64");
    const aedBase64 = aed.toString("base64");
    // Encode data, key, and AED using Base64
    const dataBase64 = Buffer.from(file).toString("base64");
    // Second Encryption: Using C++ program via stdin/stdout
    const cppProcess = spawn("criptarebased.exe");

    // Write the Base64-encoded data, key, and AED to the C++ program via stdin
    cppProcess.stdin.write(dataBase64 + "\n");
    cppProcess.stdin.write(keyBase64 + "\n");
    cppProcess.stdin.write(aedBase64 + "\n");
    cppProcess.stdin.end();

    let stdoutData = "";
    cppProcess.stdout.on("data", (data) => {
      stdoutData += data.toString();
    });
    let stderrData = "";
    cppProcess.stderr.on("data", (data) => {
      stderrData += data.toString();
    });
    cppProcess.on("close", (code) => {
      if (code !== 0) {
        console.error("C++ program exited with error code:", code);
        console.error("C++ program stderr output:", stderrData);

        res
          .status(500)
          .send(
            "Error during the second encryption process: " + stderrData.trim()
          );
        return;
      }

      let timeTakenSecond = 0;
      let authTagCpp = "";
      const timeMatch = stdoutData.match(/Encryption time: (\d+\.\d+) ms/);
      const tagMatch = stdoutData.match(/Tag from the c\+\+ program: (.+)/);

      if (timeMatch && timeMatch[1]) {
        timeTakenSecond = parseFloat(timeMatch[1]);
      } else {
        const timeMatch2 = stdoutData.match(/Encryption time: (\d+) ms/);
        if (timeMatch2 && timeMatch2[1]) {
          timeTakenSecond = parseFloat(timeMatch2[1]);
        }
      }
      if (tagMatch && tagMatch[1]) {
        authTagCpp = tagMatch[1].trim();
      }

      console.log(`Second Encryption Auth Tag: ${authTagCpp}`);
      console.log(`Second Encryption Time taken: ${timeTakenSecond} ms`);

      // Get the current local time
      const currentDate = new Date();
      const offset = currentDate.getTimezoneOffset();
      const localDate = new Date(currentDate.getTime() - offset * 60 * 1000);
      const formattedDate = localDate
        .toISOString()
        .replace("T", " ")
        .substring(0, 19);

      // Save the encryption times to the database
      const insertQuery = `
        INSERT INTO encryption (username, first_encryption_time, second_encryption_time, timestamp, name) 
        VALUES (?, ?, ?, ?, ?)`;

      db.run(
        insertQuery,
        [username, timeTakenFirst, timeTakenSecond, formattedDate, filename],
        function (err) {
          if (err) {
            console.error("Error inserting data into the database:", err);
            res
              .status(500)
              .send("Error saving encryption times to the database");
            return;
          }

          console.log("Encryption times saved successfully.");
          res.status(200).json({ success: true });
        }
      );
    });
  };

  fs.readFile(file.path, (err, fileContent) => {
    if (err) {
      console.error("Error reading uploaded file:", err);
      res.status(500).send("Error reading uploaded file");
      fs.unlinkSync(file.path); // Clean up the uploaded file

      return;
    }
    // Ensure the encryption table exists
    const createTableQuery = `
     CREATE TABLE IF NOT EXISTS encryption (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       username TEXT,
       first_encryption_time REAL,
       second_encryption_time REAL,
       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
       name TEXT
     )
   `;

    db.run(createTableQuery, (err) => {
      if (err) {
        console.error("Error creating the encryption table:", err);
        res.status(500).send("Error creating the encryption table.");
        return;
      }
    });

    handleEncryption(fileContent, file.originalname);

    fs.unlinkSync(file.path); // Clean up the uploaded file
  });
});

app.post("/encrypt", (req, res) => {
  const createTableQuery = `
      CREATE TABLE IF NOT EXISTS encryption (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        first_encryption_time REAL,
        second_encryption_time REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        name TEXT
      )
    `;

  db.run(createTableQuery, (err) => {
    if (err) {
      console.error("Error creating the encryption table:", err);
      res.status(500).send("Error creating the encryption table.");
      return;
    }
  });
  const { content } = req.body;

  if (!content) {
    res.status(400).send("Content is missing");
    return;
  }

  const username = req.cookies.username;
  if (!username) {
    res.status(401).send("You must be logged in to perform this action.");
    return;
  }

  const key = Buffer.from("feffe9928665731c6d6a8f9467308308", "hex");
  const iv = Buffer.alloc(12, 0); // 12 zero bytes IV
  const aed = Buffer.from("", "utf-8");

  // First Encryption: AES-GCM in Node.js
  const startFirstEncryption = process.hrtime();
  const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);
  let encrypted = cipher.update(content, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  const endFirstEncryption = process.hrtime(startFirstEncryption);
  const timeTakenFirst =
    (endFirstEncryption[0] * 1e9 + endFirstEncryption[1]) / 1e6; // time in milliseconds

  console.log("First Encryption Auth Tag:", authTag);
  console.log(`First Encryption Time taken: ${timeTakenFirst} ms`);

  // Convert the hex string to a Buffer
  const keyBuffer = Buffer.from("feffe9928665731c6d6a8f9467308308", "utf-8");

  // Encode the Buffer to a Base64 string
  // Encode data, key, and AED using Base64
  const dataBase64 = Buffer.from(content, "utf-8").toString("base64");

  // Check if the Base64 encoded data exceeds the size limit
  const sizeLimit = 0x1fffffe8;
  if (dataBase64.length > sizeLimit) {
    console.error("Error: Encoded data exceeds the size limit.");
    res
      .status(413) // HTTP status code 413: Payload Too Large
      .send(
        "Content is too large to be encrypted. The encoded data exceeds the size limit."
      );
    return;
  }

  const keyBase64 = keyBuffer.toString("base64");
  const aedBase64 = aed.toString("base64");

  // Second Encryption: Using C++ program via stdin/stdout
  const cppProcess = spawn("criptarebased.exe");

  // Write the Base64-encoded data, key, and AED to the C++ program via stdin
  cppProcess.stdin.write(dataBase64 + "\n");
  cppProcess.stdin.write(keyBase64 + "\n");
  cppProcess.stdin.write(aedBase64 + "\n");
  cppProcess.stdin.end();

  let stdoutData = "";
  cppProcess.stdout.on("data", (data) => {
    stdoutData += data.toString();
  });
  let stderrData = "";
  cppProcess.stderr.on("data", (data) => {
    stderrData += data.toString();
  });
  cppProcess.on("close", (code) => {
    if (code !== 0) {
      console.error("C++ program exited with error code:", code);
      console.error("C++ program stderr output:", stderrData);

      res
        .status(500)
        .send(
          "Error during the second encryption process: " + stderrData.trim()
        );
      return;
    }

    // If the C++ program ran successfully, continue with processing stdout
    let timeTakenSecond = 0;
    let authTagCpp = "";
    const timeMatch = stdoutData.match(/Encryption time: (\d+\.\d+) ms/);
    const tagMatch = stdoutData.match(/Tag from the c\+\+ program: (.+)/);
    if (timeMatch && timeMatch[1]) {
      timeTakenSecond = parseFloat(timeMatch[1]);
    } else {
      const timeMatch2 = stdout.match(/Encryption time: (\d+) ms/);
      if (timeMatch2 && timeMatch2[1]) {
        timeTakenSecond = parseFloat(timeMatch2[1]);
      }
    }
    if (tagMatch && tagMatch[1]) {
      authTagCpp = tagMatch[1].trim();
    }
    console.log(`Second Encryption Auth Tag: ${authTagCpp}`);
    console.log(`Second Encryption Time taken: ${timeTakenSecond} ms`);

    // Get the current local time
    const currentDate = new Date();
    const offset = currentDate.getTimezoneOffset();
    const localDate = new Date(currentDate.getTime() - offset * 60 * 1000);
    const formattedDate = localDate
      .toISOString()
      .replace("T", " ")
      .substring(0, 19);

    // Save the encryption times to the database
    const insertQuery = `
      INSERT INTO encryption (username, first_encryption_time, second_encryption_time, timestamp) 
      VALUES (?, ?, ?, ?)`;

    db.run(
      insertQuery,
      [username, timeTakenFirst, timeTakenSecond, formattedDate],
      function (err) {
        if (err) {
          console.error("Error inserting data into the database:", err);
          res.status(500).send("Error saving encryption times to the database");
          return;
        }

        console.log("Encryption times saved successfully.");
        res
          .status(200)
          .send("Encryption successful and times saved to the database.");
      }
    );
  });
});

app.get("/creare-bd", (req, res) => {
  db.serialize(() => {
    // Create the 'produse' table if it doesn't exist
    db.run(
      "CREATE TABLE IF NOT EXISTS produse (id INTEGER PRIMARY KEY AUTOINCREMENT, nume TEXT UNIQUE, pret REAL)",
      (err) => {
        if (err) throw err;
        console.log(
          'Tabela "produse" a fost creată cu succes sau deja există.'
        );

        const drinks = [
          { id: 1, nume: "Cola", pret: 2.5 },
          { id: 2, nume: "Limonadă", pret: 1.8 },
          { id: 3, nume: "Suc de Portocale", pret: 3.2 },
          { id: 4, nume: "Ceai Rece", pret: 2.0 },
          { id: 5, nume: "Cafea", pret: 2.7 },
        ];

        const insertQuery =
          "INSERT OR IGNORE INTO produse (id, nume, pret) VALUES (?, ?, ?)";
        drinks.forEach((drink) => {
          db.run(
            insertQuery,
            [drink.id, drink.nume, drink.pret],
            function (err) {
              if (err) throw err;
              if (this.changes > 0) {
                console.log(`Băutură "${drink.nume}" adăugată cu succes.`);
              } else {
                console.log(`Băutură "${drink.nume}" deja există în tabel.`);
              }
            }
          );
        });

        db.run(
          `CREATE TABLE IF NOT EXISTS encryption (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            first_encryption_time REAL,
            second_encryption_time REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            Name TEXT
          )`,
          (err) => {
            if (err) throw err;
            console.log(
              'Tabela "encryption" a fost creată cu succes sau deja există.'
            );
          }
        );
        db.run(
          `CREATE TABLE IF NOT EXISTS encryption_performance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    char_length INTEGER,
    nodejs_encryption_time REAL,
    cpp_encryption_time REAL
)`,
          (err) => {
            if (err) throw err;
            console.log(
              'Tabela "encryption_performance" a fost creată cu succes sau deja există.'
            );
          }
        );
        res.redirect("/");
      }
    );
  });
});
// Encryption analysis route
// Encryption analysis route
app.get("/encryption_analysis", (req, res) => {
  const username = req.cookies.username;

  // Ensure the user is authenticated
  if (!username) {
    return res.status(401).send("You must be logged in to access this data.");
  }

  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS encryption_performance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      char_length INTEGER,
      nodejs_encryption_time REAL,
      cpp_encryption_time REAL
    )
  `;

  // Create the table if it doesn't exist
  db.run(createTableQuery, (err) => {
    if (err) {
      console.error("Error creating table:", err);
      return res
        .status(500)
        .send("Error creating the encryption performance table.");
    }

    // Table creation succeeded, now run the query
    const query = `
      SELECT char_length, nodejs_encryption_time, cpp_encryption_time
      FROM encryption_performance 
      WHERE user_id = ?
      ORDER BY char_length ASC
    `;

    db.all(query, [username], (err, rows) => {
      if (err) {
        console.error(
          `Error fetching encryption performance data for ${username}:`,
          err
        );
        return res
          .status(500)
          .send("Error fetching encryption performance data.");
      }

      if (rows.length === 0) {
        // No data available for this user
        return res.render("encryption_analysis", {
          dataAvailable: false,
          username: username,
        });
      }

      // Data is available, render the page with the performance data
      res.render("encryption_analysis", {
        dataAvailable: true,
        performanceData: rows,
        username: username,
      });
    });
  });
});

let userProgress = {};
// Encryption progress route
app.get("/encryption-progress", (req, res) => {
  const username = req.cookies.username;

  if (!username) {
    return res.status(401).send("You must be logged in to view progress.");
  }

  if (userProgress[username]) {
    return res.json({
      running: userProgress[username].running,
      progress: userProgress[username].progress,
    });
  } else {
    return res.json({ running: false, progress: 0 });
  }
});

let activeCppProcesses = 0;
const maxConcurrentCppProcesses = 10;

app.post("/encrypt-performance-test", (req, res) => {
  const username = req.cookies.username;
  let responseSent = false;

  const sendResponse = (statusCode, message) => {
    if (!responseSent) {
      responseSent = true;
      userProgress[username].running = false;
      res.status(statusCode).json({ message });
    }
  };

  if (!username) {
    return sendResponse(401, "You must be logged in to perform this action.");
  }

  const { nodeMin, nodeMax, nodeStep, cppMin, cppMax, cppStep } = req.body;

  if (
    ![nodeMin, nodeMax, nodeStep, cppMin, cppMax, cppStep].every(
      (val) => Number.isInteger(val) && val >= 0
    ) ||
    nodeMin > nodeMax ||
    cppMin > cppMax ||
    nodeStep <= 0 ||
    cppStep <= 0
  ) {
    return sendResponse(
      400,
      "Invalid input. Ensure min <= max and step > 0 for all values."
    );
  }

  if (nodeMax > 100000000 || cppMax > 0x1fffffe8) {
    return sendResponse(
      400,
      "Max character limit exceeded for Node.js or C++."
    );
  }

  if (userProgress[username] && userProgress[username].running) {
    return sendResponse(429, "running");
  }

  userProgress[username] = { running: true, progress: 0 };

  const key = Buffer.from("feffe9928665731c6d6a8f9467308308", "hex");
  const iv = Buffer.alloc(12, 0);
  const aed = Buffer.from("", "utf-8");

  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS encryption_performance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      char_length INTEGER,
      nodejs_encryption_time REAL,
      cpp_encryption_time REAL
    )
  `;

  db.run(createTableQuery, (err) => {
    if (err) {
      console.log("Error creating table:", err);
      return sendResponse(500, "error");
    }

    db.run(
      "DELETE FROM encryption_performance WHERE user_id = ?",
      [username],
      (err) => {
        if (err) {
          console.log("Error deleting old data:", err);
          return sendResponse(500, "error");
        }

        const results = new Map();

        const performEncryption = (method, charLength) => {
          return new Promise((resolve, reject) => {
            const content = "A".repeat(charLength);

            if (method === "node") {
              try {
                const start = process.hrtime();
                const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);
                cipher.update(content, "utf8", "hex");
                cipher.final("hex");
                const end = process.hrtime(start);
                const timeTaken = (end[0] * 1e9 + end[1]) / 1e6;

                const result = results.get(charLength) || {
                  user_id: username,
                  char_length: charLength,
                  nodejs_encryption_time: null,
                  cpp_encryption_time: null,
                };

                result.nodejs_encryption_time = timeTaken;
                results.set(charLength, result);

                userProgress[username].progress = (
                  (charLength / (nodeMax + cppMax)) *
                  100
                ).toFixed(2);

                resolve();
              } catch (err) {
                console.log("Error during Node.js encryption:", err);
                reject(err);
              }
            } else if (method === "cpp") {
              const runCppProcess = () => {
                const cppProcess = spawn("criptarebased.exe");
                activeCppProcesses++;
                cppProcess.stdin.write(
                  Buffer.from(content).toString("base64") + "\n"
                );
                const key2 = Buffer.from(
                  "feffe9928665731c6d6a8f9467308308",
                  "utf-8"
                );
                cppProcess.stdin.write(key2.toString("base64") + "\n");
                cppProcess.stdin.write(aed.toString("base64") + "\n");
                cppProcess.stdin.end();

                let stdoutData = "";
                cppProcess.stdout.on(
                  "data",
                  (data) => (stdoutData += data.toString())
                );

                cppProcess.on("close", (code) => {
                  activeCppProcesses--;
                  if (code !== 0) {
                    console.log("C++ process exited with code:", code);
                    return reject(new Error("C++ encryption error"));
                  }

                  const match = stdoutData.match(
                    /Encryption time: (\d+\.\d+) ms/
                  );
                  const timeTaken = match ? parseFloat(match[1]) : 0;

                  const result = results.get(charLength) || {
                    user_id: username,
                    char_length: charLength,
                    nodejs_encryption_time: null,
                    cpp_encryption_time: null,
                  };

                  result.cpp_encryption_time = timeTaken;
                  results.set(charLength, result);

                  // C++ progress calculation
                  userProgress[username].progress = (
                    ((charLength + nodeMax) / (nodeMax + cppMax)) *
                    100
                  ).toFixed(2);
                  resolve();
                });
              };

              const waitForSlot = () => {
                if (activeCppProcesses < maxConcurrentCppProcesses) {
                  runCppProcess();
                } else {
                  setTimeout(waitForSlot, 100);
                }
              };

              waitForSlot();
            }
          });
        };

        const startEncryptionTasks = async () => {
          const tasks = [];

          for (let i = nodeMin; i <= nodeMax; i += nodeStep) {
            tasks.push(performEncryption("node", i));
          }

          for (let i = cppMin; i <= cppMax; i += cppStep) {
            tasks.push(performEncryption("cpp", i));
          }

          try {
            await Promise.all(tasks);
            insertResultsIntoDatabase();
          } catch (err) {
            console.log("Error during encryption tasks:", err);
            return sendResponse(500, "error");
          }
        };

        const insertResultsIntoDatabase = () => {
          const insertQuery = `
            INSERT INTO encryption_performance (user_id, char_length, nodejs_encryption_time, cpp_encryption_time)
            VALUES (?, ?, ?, ?)
          `;

          db.serialize(() => {
            const stmt = db.prepare(insertQuery);
            for (const result of results.values()) {
              stmt.run([
                result.user_id,
                result.char_length,
                result.nodejs_encryption_time,
                result.cpp_encryption_time,
              ]);
            }
            stmt.finalize(() => sendResponse(200, "finished"));
          });
        };

        startEncryptionTasks();
      }
    );
  });
});

app.get("/inserare-bd", (req, res) => {
  db.serialize(() => {
    // Connect to the database server and open a connection to the database

    if (db.err) throw db.err;

    console.log("Conexiunea la baza de date a fost realizată cu succes.");

    // Insert multiple cocktails into the 'produse' table
    const cocktails = [
      { id: 6, nume: "Mojito", pret: 15.0 },
      { id: 7, nume: "Cosmopolitan", pret: 12.5 },
      { id: 8, nume: "Piña Colada", pret: 10.99 },
      { id: 9, nume: "Margarita", pret: 11.75 },
      { id: 10, nume: "Daiquiri", pret: 13.25 },
    ];

    const insertQuery =
      "REPLACE INTO produse (id, nume, pret) VALUES (?, ?, ?);";
    cocktails.forEach((cocktail) => {
      db.run(
        insertQuery,
        [cocktail.id, cocktail.nume, cocktail.pret],
        (err) => {
          if (err) throw err;
          console.log(
            `Cocktail-ul "${cocktail.nume}" a fost inserat cu succes.`
          );
        }
      );
    });
    // Redirect the client to "/"
    res.redirect("/");
  });
});

var cart = session.cart || [];

db = new sqlite3.Database("cumparaturi.db", (err) => {
  if (err) {
    console.error(err.message);
    throw err;
  }
  console.log("Connected to the database.");
});

app.post("/adaugare_cos", (req, res) => {
  const productId = req.body.id;
  // Fetch the product details from the database using the product ID
  db.get("SELECT * FROM produse WHERE id = ?", [productId], (err, product) => {
    if (err) throw err;
    if (product) {
      // Add the product object to the cart array
      cart.push(product);
      res.redirect("/"); // Redirect the user to the main page
    } else {
      res.status(404).send("Product not found."); // Send a response back to the client if the product doesn't exist
    }
  });
});

app.get("/vizualizare-cos", (req, res) => {
  // Retrieve the cart from the session or initialize an empty array

  // Define the calculateTotal function within the scope of the route handler
  function calculateTotal(cart) {
    let total = 0;
    const quantityMap = {}; // Map to track the quantity of each product ID

    // Calculate the quantity for each product in the cart
    cart.slice(0, cart.length - 1).forEach((product) => {
      const productId = product.id;
      quantityMap[productId] = (quantityMap[productId] || 0) + 1;
    });

    // Iterate over the quantity map to calculate the total
    Object.keys(quantityMap).forEach((productId) => {
      const product = cart.find((item) => item.id === parseInt(productId));
      if (product) {
        const price = parseFloat(product.pret); // Ensure price is a number
        const quantity = quantityMap[productId];
        if (!isNaN(price) && !isNaN(quantity)) {
          total += price * quantity;
        }
      }
    });

    return total;
  }

  const total = calculateTotal(cart);
  res.render("vizualizare-cos", { cart: cart, total: total });
});
app.get("/autentificare", (req, res) => {
  req.session.username = null;
  res.clearCookie("username");
  res.clearCookie("admin");
  res.clearCookie("mesajEroare");
  res.render("autentificare", { req });
});
const fs = require("fs");
const { stderr } = require("process");
const usersData = fs.readFileSync("utilizatori.json");
const users = JSON.parse(usersData);

const failedLoginAttemptsShortInterval = 3;

// Map to store failed login attempts for each user
const failedLoginAttempts = new Map();

app.post("/verificare-autentificare", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (user) => user.utilizator === username && user.parola === password
  );
  console.log("verificare-autentificare apelat");
  if (user) {
    console.log("Logat");

    // Reset failed login attempts for the user
    failedLoginAttempts.delete(username);
    failedLoginAttempts.delete(username + "-blockTime");

    // Store user session and set cookies
    req.session.utilizator = user.utilizator;
    req.session.nume = user.nume;
    req.session.prenume = user.prenume;
    res.cookie("username", user.utilizator);

    // Set admin status in session or cookie
    if (user.admin) {
      req.session.admin = true;
      res.cookie("admin", "true");
    } else {
      req.session.admin = false;
      res.cookie("admin", "false");
    }

    res.redirect("/");
  } else {
    console.log("Nelogat");
    // Increment failed login attempts for the user
    let attempts = failedLoginAttempts.get(username) || 0;
    attempts++;
    failedLoginAttempts.set(username, attempts);

    // Check if the user exceeds the maximum number of failed login attempts
    if (attempts >= failedLoginAttemptsShortInterval) {
      failedLoginAttempts.set(username + "-blockTime", Date.now());
      req.session.errorMessage =
        "Accesul este blocat temporar. Încercați din nou mai târziu.";
      res.cookie(
        "mesajEroare",
        "Accesul este blocat temporar. Încercați din nou mai târziu."
      );
      return res.redirect("/autentificare");
    } else {
      // Check if the user is currently blocked
      const blockTime = failedLoginAttempts.get(username + "-blockTime");
      if (blockTime) {
        const currentTime = Date.now();
        const blockDuration = 10000; // Block duration in milliseconds (e.g., 10 seconds)
        const timeSinceBlock = currentTime - blockTime;
        if (timeSinceBlock < blockDuration) {
          const timeLeft = blockDuration - timeSinceBlock;
          req.session.errorMessage = `Accesul este blocat temporar. Încercați din nou în ${Math.ceil(
            timeLeft / 1000
          )} secunde.`;
          res.cookie(
            "mesajEroare",
            `Accesul este blocat temporar. Încercați din nou în ${Math.ceil(
              timeLeft / 1000
            )} secunde.`
          );
          return res.redirect("/autentificare");
        } else {
          // Reset failed login attempts if the block duration has passed
          failedLoginAttempts.delete(username);
          failedLoginAttempts.delete(username + "-blockTime");
        }
      }
    }

    req.session.errorMessage = "Nume de utilizator sau parolă greșite.";
    res.cookie("mesajEroare", "Username sau parola gresita");
    res.redirect("/autentificare");

    console.log("Username sau parola gresita");
  }
});

app.get("/inregistrare", (req, res) => {
  res.render("inregistrare", { errorMessage: null });
});
app.post("/inregistrare", (req, res) => {
  const { username, password } = req.body;

  // Check if the username already exists
  const userExists = users.some((user) => user.utilizator === username);
  if (userExists) {
    // Render the registration page with an error message
    return res.render("inregistrare", {
      errorMessage: "Username already exists. Please choose another one.",
    });
  }

  // Add new user with admin set to false
  const newUser = { utilizator: username, parola: password, admin: false };
  users.push(newUser);

  // Save the updated user list back to the file
  fs.writeFile("utilizatori.json", JSON.stringify(users, null, 2), (err) => {
    if (err) {
      console.error("Error saving user data:", err);
      return res.status(500).send("Internal Server Error");
    }

    // Redirect to the login page after successful registration
    res.redirect("/autentificare");
  });
});

app.get("/upload_file", (req, res) => {
  res.render("upload_file");
});
// la accesarea din browser adresei http://localhost:6789/chestionar se va apela funcțiaspecificată
app.get("/chestionar", (req, res) => {
  const fs = require("fs");

  // Read the contents of the JSON file
  const intrebariData = fs.readFileSync("intrebari.json");
  const listaIntrebari = JSON.parse(intrebariData);
  // în fișierul views/chestionar.ejs este accesibilă variabila 'intrebari' careconține vectorul de întrebări
  res.render("chestionar", { intrebari: listaIntrebari });
});
app.post("/rezultat-chestionar", (req, res) => {
  const intrebariData = fs.readFileSync("intrebari.json");
  const intrebari = JSON.parse(intrebariData);

  const raspunsuri = [];
  for (let i = 0; i < intrebari.length; i++) {
    const answer = req.body[`raspuns${i}`];

    // Check if the answer exists; if not, handle it (e.g., set to null)
    if (answer) {
      raspunsuri.push(answer[0]); // If answer exists, push it to raspunsuri array
    } else {
      raspunsuri.push(null); // If no answer, push null or handle as needed
    }
  }

  const variante = intrebari.map((intrebare) => intrebare.variante[0]);

  console.log(intrebari, variante, raspunsuri);
  res.render("rezultat-chestionar", { intrebari, variante, req, raspunsuri });
});

app.get("/admin", (req, res) => {
  const admin = req.cookies.admin === "true";
  db.serialize(() => {
    // Fetch all products from the 'produse' table
    db.all("SELECT * FROM produse", (err, rows) => {
      if (err) throw err;
      res.render("admin", {
        products: rows,
        username: req.cookies.username,
        admin: admin,
      });
    });
  });
});
app.post("/admin/adauga-produs", (req, res) => {
  db = new sqlite3.Database("cumparaturi.db");
  const { nume, pret } = req.body;

  // Inserează produsul în baza de date
  const insertQuery = "INSERT INTO produse (nume, pret) VALUES (?, ?)";
  db.run(insertQuery, [nume, pret], function (err) {
    if (err) {
      console.error(err);
      res.redirect("/admin"); // Redirecționează înapoi la pagina de admin în caz de eroare
      return;
    }

    console.log(`Produsul "${nume}" a fost adăugat cu succes.`);
    res.redirect("/admin"); // Redirecționează înapoi la pagina de admin după adăugare
  });
});

app.all("*", (req, res) => {
  const internetprotol = req.ip;

  accessAttempts.set(
    internetprotol,
    (accessAttempts.get(internetprotol) || 0) + 1
  );

  accessAttempts.set(internetprotol + "-blockTime", Date.now());
  res.status(404).send("The page wasn't found.");
});
app.listen(port, () =>
  console.log(`Serverul rulează la adresa http://localhost:6789`)
);
