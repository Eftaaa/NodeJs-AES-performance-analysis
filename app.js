const cookieParser = require("cookie-parser");
const express = require("express");
const expressLayouts = require("express-ejs-layouts");
const bodyParser = require("body-parser");
const app = express();
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });
const { spawn } = require("child_process");
const bcrypt = require("bcrypt");
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

let redirectingflag = false;

app.use((req, res, next) => {
  if (!req.session.aesKey || req.session.aesKey == null) {
    console.log("AES key is not set. Skipping encryption.");
    return next(); // Skip encryption and continue to the next middleware/route
  }

  const originalSend = res.send;
  const originalRedirect = res.redirect;
  res.redirect = async function (url) {
    try {
      if (!req.session.aesKey) {
        console.log("No AES key. Sending plain redirect.");
        return originalRedirect.call(this, url);
      }

      const aesKey = Buffer.from(req.session.aesKey, "hex");
      const sequenceNumber = ++req.session.sequenceNumber || 1;
      const iv = generateIV(sequenceNumber);
      const aad = "";

      const redirectData = JSON.stringify({ isRedirect: true, url });

      const { encryptedmsg, authTagCpp } = await encryptAESWithCPP(
        redirectData,
        aesKey,
        aad,
        iv
      );

      const encryptedDataBase64 = Buffer.from(encryptedmsg).toString("base64");
      const authTagBase64 = Buffer.from(authTagCpp, "utf-8").toString("base64");
      const aadBase64 = Buffer.from(aad).toString("base64");
      const ivHex = iv.toString("hex");

      res.locals.isEncrypted = true;

      // Send encrypted redirect response
      return originalSend.call(this, {
        encryptedData: encryptedDataBase64,
        authTag: authTagBase64,
        aad: aadBase64,
        iv: ivHex,
      });
    } catch (err) {
      console.error("Redirect encryption failed:", err);
      res.status(500).send("Redirect encryption failed");
    }
  };
  res.send = async function (data) {
    try {
      // Prevent recursive encryption
      if (res.locals.isEncrypted) {
        return originalSend.call(this, data);
      }


      const redirectData = JSON.stringify({ isRedirect: false, data });

      const aesKey = Buffer.from(req.session.aesKey, "hex");
      await console.log(aesKey);

      const sequenceNumber = ++req.session.sequenceNumber || 1;
      const iv = generateIV(sequenceNumber);

      const aad = "";

      const { encryptedmsg, authTagCpp } = await encryptAESWithCPP(
        redirectData,
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

      return next();
    }
  };

  next();
});

app.get("/public-key", (req, res) => {
  res.json({ publicKey });
});

// Endpoint to receive encrypted AES key from the client
app.post("/exchange-key", (req, res) => {
  const encryptedAESKey = Buffer.from(req.body.encryptedKey, "base64");
  const decryptedAESKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedAESKey
  );
  req.session.aesKey = decryptedAESKey.toString("hex");
  res.sendStatus(200);
});

function encryptAESWithCPP(data, key, aad, iv) {
  return new Promise((resolve, reject) => {

    const dataBase64 = Buffer.from(data).toString("base64");

    const keyBase64 = Buffer.from(
      Buffer.from(key).toString("hex"),
      "utf-8"
    ).toString("base64");

    const aadBase64 = Buffer.from(aad).toString("base64");

    const ivHex = Buffer.from(iv);

    const ivBase64 = Buffer.from(ivHex, "hex").toString("base64");

    const cppProcess = spawn("./criptarebase64aesgcm.exe");

    let encryptedOutput = "";
    let errorOutput = "";

    cppProcess.stdout.on("data", (chunk) => {
      encryptedOutput += chunk.toString();
    });

    cppProcess.stderr.on("data", (chunk) => {
      errorOutput += chunk.toString();
    });

    cppProcess.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(
            `Encryption program exited with code ${code}: ${errorOutput}`
          )
        );
      } else {
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
          authTagCpp,
          timeTakenSecond,
        });
      }
    });

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
function decryptAESWithCPP(data, key, aad, iv, tag) {
  return new Promise((resolve, reject) => {

    const dataBase64 = Buffer.from(data).toString("base64");

    const keyBase64 = Buffer.from(
      Buffer.from(key).toString("hex"),
      "utf-8"
    ).toString("base64");

    const aadBase64 = Buffer.from(aad).toString("base64");

    const ivHex = Buffer.from(iv).toString("hex");
    const ivBase64 = Buffer.from(ivHex, "utf-8").toString("base64");
    const tagBase64 = Buffer.from(tag).toString("base64");

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
        let encryptedmsg = "";

        // Match for encrypted message
        const enctextmatch = encryptedOutput.match(/P:\s([\s\S]*)/);
        if (enctextmatch && enctextmatch[1]) {
          // Remove any unnecessary whitespace and concatenate lines
          const hexString = enctextmatch[1].replace(/\s+/g, "");
          encryptedmsg = Buffer.from(hexString, "hex");
        }

        // Resolve with the parsed values
        resolve({
          encryptedmsg, // Encrypted message as a Buffer
        });
      }
    });

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

function generateIV(sequenceNumber) {
  const ivBuffer = Buffer.alloc(12);

  ivBuffer.writeUInt32BE(sequenceNumber, 8); // Position it at offset 8
  return ivBuffer.toString("hex");
}

app.post("/reset-session", (req, res) => {
  req.session.aesKey = null;
  req.session.sequenceNumber = 0;
  req.session.destroy((err) => {
    if (err) {
      console.error("Failed to save session:", err);
      return res.status(500).send("Failed to reset session");
    }
    console.log("Session reset successfully");
    res.sendStatus(200);
  });
  res.clearCookie("connect.sid");
});
app.get("/", (req, res) => {
  const admin = req.cookies.admin === "true";
  const username = req.cookies.username;
  const authenticated = username ? true : false;

  const db = new sqlite3.Database("cumparaturi.db", sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
      console.error("Database connection error:", err);
      return res.render("index", { products: [], authenticated, admin });
    }

    db.serialize(() => {
      db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='produse'", (err, table) => {
        if (err) {
          console.error("Error checking for produse table:", err);
          return res.status(500).send("Error checking for product table.");
        }

        if (!table) {
          return res.render("demo_page", { products: [], authenticated, admin, username });
        }

        let query = `SELECT p.id, p.nume, p.pret, p.stoc, COALESCE(SUM(ci.quantity), 0) AS cart_quantity
                     FROM produse p
                     LEFT JOIN cart_item ci ON p.id = ci.product_id
                     LEFT JOIN cart c ON ci.cart_id = c.id AND c.customer_id = (SELECT id FROM customers WHERE name = ?)
                     GROUP BY p.id`;

        db.all(query, [username], (err, rows) => {
          if (err) {
            console.error("Error fetching products with cart quantities:", err);
            return res.status(500).send("Error fetching products.");
          }

          console.log("Fetched products:", rows);
          res.render("demo_page", {
            products: rows,
            authenticated,
            admin,
            username
          });
        });
      });
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
  const fileBuffer = req.file.buffer;
  const fileName = req.file.originalname;

  if (!fileBuffer) {
    res.status(400).send("File is missing");
    return;
  }

  const username = req.cookies.username;
  if (!username) {
    res.status(401).send("You must be logged in to perform this action.");
    return;
  }

  const key = Buffer.from(req.session.aesKey, "hex");
  const iv = Buffer.alloc(12, 0);
  const aed = Buffer.from("", "utf-8");

  const handleEncryption = (file, filename) => {
    // First Encryption: AES-GCM in Node.js
    const startFirstEncryption = process.hrtime();

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    let encrypted = cipher.update(file, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");
    const endFirstEncryption = process.hrtime(startFirstEncryption);
    const timeTakenFirst =
      (endFirstEncryption[0] * 1e9 + endFirstEncryption[1]) / 1e6; // time in milliseconds

    console.log("First Encryption Auth Tag:", authTag);
    console.log(`First Encryption Time taken: ${timeTakenFirst} ms`);

    const keyBuffer = Buffer.from(req.session.aesKey, "utf8");

    const keyBase64 = keyBuffer.toString("base64");

    const aedBase64 = aed.toString("base64");
    const dataBase64 = Buffer.from(file).toString("base64");
    // Second Encryption: Using C++ program via stdin/stdout
    const cppProcess = spawn("criptarebased.exe");

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
      console.log(`Second Encryption Time taken: ${stdoutData} ms`);

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

          // After inserting, check if there are more than 10 entries for the same username
          const checkQuery = `
          SELECT COUNT(*) AS count FROM encryption WHERE username = ?`;

          db.get(checkQuery, [username], (err, row) => {
            if (err) {
              console.error("Error checking entry count:", err);
              res.status(500).send("Error checking entry count.");
              return;
            }

            if (row.count > 10) {
              // If there are more than 10 entries, delete the oldest ones
              const deleteQuery = `
              DELETE FROM encryption WHERE id IN (
                SELECT id FROM encryption WHERE username = ? ORDER BY timestamp ASC LIMIT ? OFFSET ?
              )`;

              const excessEntriesCount = row.count - 10;
              db.run(
                deleteQuery,
                [username, excessEntriesCount, 0],
                function (err) {
                  if (err) {
                    console.error("Error deleting old entries:", err);
                    res.status(500).send("Error deleting old entries.");
                    return;
                  }

                  console.log("Old entries deleted successfully.");
                }
              );
            }
          });
          console.log("Encryption times saved successfully.");
          res.status(200).json({ success: true });
        }
      );
    });
  };

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
  handleEncryption(fileBuffer, fileName);
});

app.post("/encrypt", async (req, res) => {
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

  const { encryptedData, IV, tag } = req.body;

  if (!encryptedData || !IV || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(IV, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  // Decrypt using C++ program (same function as your login decryption)
  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const formData = JSON.parse(decryptedMessageString); // Parse the form data

  const content = formData;

  if (!content) {
    res.status(400).send("Content is missing");
    return;
  }

  const username = req.cookies.username;
  if (!username) {
    res.status(401).send("You must be logged in to perform this action.");
    return;
  }
  const key = Buffer.from(req.session.aesKey, "hex");
  const iv = Buffer.alloc(12, 0); // 12 zero bytes IV
  const aed = Buffer.from("", "utf-8");

  // First Encryption: AES-GCM in Node.js
  const startFirstEncryption = process.hrtime();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(content, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  const endFirstEncryption = process.hrtime(startFirstEncryption);
  const timeTakenFirst =
    (endFirstEncryption[0] * 1e9 + endFirstEncryption[1]) / 1e6; // time in milliseconds

  console.log("NodeJs Encryption Auth Tag:", authTag);
  console.log(`NodeJs Encryption Time taken: ${timeTakenFirst} ms`);

  const keyBuffer = Buffer.from(req.session.aesKey, "utf-8");

  const dataBase64 = Buffer.from(content, "utf-8").toString("base64");

  // Check if the Base64 encoded data exceeds the size limit
  const sizeLimit = 0x1fffffe8;
  if (dataBase64.length > sizeLimit) {
    console.error("Error: Encoded data exceeds the size limit.");
    res
      .status(413)
      .send(
        "Content is too large to be encrypted. The encoded data exceeds the size limit."
      );
    return;
  }

  const keyBase64 = keyBuffer.toString("base64");
  const aedBase64 = aed.toString("base64");

  const cppProcess = spawn("criptarebased.exe");

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
      const timeMatch2 = stdout.match(/Encryption time: (\d+) ms/);
      if (timeMatch2 && timeMatch2[1]) {
        timeTakenSecond = parseFloat(timeMatch2[1]);
      }
    }
    if (tagMatch && tagMatch[1]) {
      authTagCpp = tagMatch[1].trim();
    }
    console.log(`C++ Encryption Auth Tag: ${authTagCpp}`);
    console.log(`C++ Encryption Time taken: ${timeTakenSecond} ms`);

    // Get the current local time
    const currentDate = new Date();
    const offset = currentDate.getTimezoneOffset();
    const localDate = new Date(currentDate.getTime() - offset * 60 * 1000);
    const formattedDate = localDate
      .toISOString()
      .replace("T", " ")
      .substring(0, 19);

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

        // After inserting, check if there are more than 10 entries for the same username
        const checkQuery = `
          SELECT COUNT(*) AS count FROM encryption WHERE username = ?`;

        db.get(checkQuery, [username], (err, row) => {
          if (err) {
            console.error("Error checking entry count:", err);
            res.status(500).send("Error checking entry count.");
            return;
          }

          if (row.count > 10) {
            // If there are more than 10 entries, delete the oldest ones
            const deleteQuery = `
              DELETE FROM encryption WHERE id IN (
                SELECT id FROM encryption WHERE username = ? ORDER BY timestamp ASC LIMIT ? OFFSET ?
              )`;

            const excessEntriesCount = row.count - 10;
            db.run(
              deleteQuery,
              [username, excessEntriesCount, 0],
              function (err) {
                if (err) {
                  console.error("Error deleting old entries:", err);
                  res.status(500).send("Error deleting old entries.");
                  return;
                }

                console.log("Old entries deleted successfully.");
                res
                  .status(200)
                  .send(
                    "Encryption successful, times saved, and old entries deleted."
                  );
              }
            );
          } else {
            // No need to delete any entries
            res
              .status(200)
              .send("Encryption successful and times saved to the database.");
          }
        });
      }
    );
  });
});

app.get("/creare-bd", (req, res) => {
  db.serialize(() => {
    // Create the 'produse' table if it doesn't exist
    db.run(
      `CREATE TABLE IF NOT EXISTS produse (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nume TEXT UNIQUE NOT NULL,
        pret REAL NOT NULL,
        stoc INTEGER NOT NULL CHECK(stoc >= 0)
      )`,
      (err) => {
        if (err) throw err;
        console.log(
          'Tabela "produse" a fost creată cu succes sau deja există.'
        );

        const drinks = [
          { id: 1, nume: "Cola", pret: 2.5, stoc: 10 },
          { id: 2, nume: "Limonadă", pret: 1.8, stoc: 15 },
          { id: 3, nume: "Suc de Portocale", pret: 3.2, stoc: 8 },
          { id: 4, nume: "Ceai Rece", pret: 2.0, stoc: 12 },
          { id: 5, nume: "Cafea", pret: 2.7, stoc: 20 },
        ];

        const insertQuery =
          "INSERT OR IGNORE INTO produse (id, nume, pret, stoc) VALUES (?, ?, ?, ?)";
        drinks.forEach((drink) => {
          db.run(
            insertQuery,
            [drink.id, drink.nume, drink.pret, drink.stoc],
            function (err) {
              if (err) throw err;
              if (this.changes > 0) {
                console.log(
                  `Băutură "${drink.nume}" cu stoc ${drink.stoc} adăugată cu succes.`
                );
              } else {
                console.log(`Băutură "${drink.nume}" deja există în tabel.`);
              }
            }
          );
        });

        db.run(
          `CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
          )`,
          (err) => {
            if (err) throw err;
            console.log(
              'Tabela "customers" a fost creată cu succes sau deja există.'
            );
            // Insert users into the "customers" table
            const insertUserQuery =
              "INSERT OR IGNORE INTO customers (name) VALUES (?)";

            users.forEach((user) => {
              db.run(insertUserQuery, [user.utilizator], function (err) {
                if (err) throw err;
                if (this.changes > 0) {
                  console.log(
                    `Utilizator "${user.utilizator}" adăugat cu succes.`
                  );
                } else {
                  console.log(
                    `Utilizator "${user.utilizator}" deja există în tabel.`
                  );
                }
              });
            });
          }
        );

        // Create the "cart" table
        db.run(
          `CREATE TABLE IF NOT EXISTS cart (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers (id)
  )`,
          (err) => {
            if (err) throw err;
            console.log(
              'Tabela "cart" a fost creată cu succes sau deja există.'
            );
          }
        );

        // Create the "cart_item" table
        db.run(
          `CREATE TABLE IF NOT EXISTS cart_item (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cart_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL CHECK(quantity > 0),
    FOREIGN KEY (cart_id) REFERENCES cart (id),
    FOREIGN KEY (product_id) REFERENCES produse (id)
  )`,
          (err) => {
            if (err) throw err;
            console.log(
              'Tabela "cart_item" a fost creată cu succes sau deja există.'
            );
          }
        );
        // Create the "Order" table
        db.run(
          `CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      FOREIGN KEY (customer_id) REFERENCES customers (id)
    )`,
          (err) => {
            if (err) throw err;
            console.log(
              'Tabela "orders" a fost creată cu succes sau deja există.'
            );
          }
        );

        // Create the "order_item" table
        db.run(
          `CREATE TABLE IF NOT EXISTS order_item (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL CHECK(quantity > 0),
      FOREIGN KEY (order_id) REFERENCES orders (id),
      FOREIGN KEY (product_id) REFERENCES produse (id)
    )`,
          (err) => {
            if (err) throw err;
            console.log(
              'Tabela "order_item" a fost creată cu succes sau deja există.'
            );
          }
        );
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
app.get("/encryption_analysis", (req, res) => {
  const username = req.cookies.username;

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


  if (userProgress[username] && userProgress[username].running) {
    return sendResponse(429, "running");
  }
  userProgress[username] = { running: true, progress: 0 };

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

  

  

  const key = Buffer.from(req.session.aesKey, "hex");
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
                const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
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
                const key2 = Buffer.from(req.session.aesKey, "utf-8");
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
                    /Encryption time: (\d+(?:\.\d+)?) ms/
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

    if (db.err) throw db.err;

    console.log("Conexiunea la baza de date a fost realizată cu succes.");

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
app.get("/vizualizare-comenzi", (req, res) => {
  const username = req.cookies.username;

  db.get(
    "SELECT id FROM customers WHERE name = ?",
    [username],
    (err, customer) => {
      if (err) {
        console.error("Error fetching customer:", err);
        return res.status(500).send("Internal Server Error");
      }

      if (!customer) return res.status(404).send("Customer not found");

      // Fetch orders and associated items for the customer
      db.all(
        `SELECT o.id AS order_id, oi.product_id, oi.quantity, p.nume AS product_name
         FROM orders o
         JOIN order_item oi ON o.id = oi.order_id
         JOIN produse p ON oi.product_id = p.id
         WHERE o.customer_id = ?`,
        [customer.id],
        (err, rows) => {
          if (err) {
            console.error("Error fetching orders:", err);
            return res.status(500).send("Internal Server Error");
          }

          // Group items by order ID
          const orders = rows.reduce((acc, row) => {
            const order = acc.find((o) => o.id === row.order_id);
            if (order) {
              order.items.push({
                product_name: row.product_name,
                quantity: row.quantity,
              });
            } else {
              acc.push({
                id: row.order_id,
                items: [
                  { product_name: row.product_name, quantity: row.quantity },
                ],
              });
            }
            return acc;
          }, []);

          res.render("vizualizare-comenzi", { orders });
        }
      );
    }
  );
});
app.post("/sterge-comanda", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const formData = JSON.parse(decryptedMessageString); // Parse the form data
  const orderId = formData.order_id;
  // Delete order items and the order itself
  db.run("DELETE FROM order_item WHERE order_id = ?", [orderId], (err) => {
    if (err) {
      console.error("Error deleting order items:", err);
      return res.status(500).send("Internal Server Error");
    }

    db.run("DELETE FROM orders WHERE id = ?", [orderId], (err) => {
      if (err) {
        console.error("Error deleting order:", err);
        return res.status(500).send("Internal Server Error");
      }

      res.redirect("/vizualizare-comenzi");
    });
  });
});

app.post("/adaugare_cos", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageString = decrypted.encryptedmsg.toString("utf-8");
  const formData = JSON.parse(decryptedMessageString);

  const productId = formData.id;
  const quantityToAdd = 1;

  db.serialize(() => {
    db.run("BEGIN TRANSACTION;");

    db.get(
      "SELECT stoc FROM produse WHERE id = ?",
      [productId],
      (err, product) => {
        if (err) {
          db.run("ROLLBACK;");
          throw err;
        }

        if (product && product.stoc >= quantityToAdd) {
          db.run(
            "UPDATE produse SET stoc = stoc - ? WHERE id = ? AND stoc >= ?",
            [quantityToAdd, productId, quantityToAdd],
            function (err) {
              if (err || this.changes === 0) {
                db.run("ROLLBACK;");
                res.status(400).send("Not enough stock available.");
                return;
              }

              const username = req.cookies.username;
              db.get(
                "SELECT id FROM customers WHERE name = ?",
                [username],
                (err, customer) => {
                  if (err || !customer) {
                    db.run("ROLLBACK;");
                    res.status(404).send("Customer not found.");
                    return;
                  }

                  db.get(
                    "SELECT id FROM cart WHERE customer_id = ?",
                    [customer.id],
                    (err, cart) => {
                      if (err) {
                        db.run("ROLLBACK;");
                        throw err;
                      }

                      let cartId = cart ? cart.id : null;
                      if (!cartId) {
                        db.run(
                          "INSERT INTO cart (customer_id) VALUES (?)",
                          [customer.id],
                          function (err) {
                            if (err) {
                              db.run("ROLLBACK;");
                              throw err;
                            }
                            cartId = this.lastID;
                            insertCartItem(cartId, productId, quantityToAdd);
                          }
                        );
                      } else {
                        insertCartItem(cartId, productId, quantityToAdd);
                      }
                    }
                  );
                }
              );
            }
          );
        } else {
          db.run("ROLLBACK;");
          res.status(400).send("Not enough stock available.");
        }
      }
    );

    function insertCartItem(cartId, productId, quantityToAdd) {
      db.get(
        "SELECT quantity FROM cart_item WHERE cart_id = ? AND product_id = ?",
        [cartId, productId],
        (err, item) => {
          if (err) {
            db.run("ROLLBACK;");
            return res.status(500).send("Database error checking cart item.");
          }

          if (item) {
            const newQuantity = item.quantity + quantityToAdd;
            db.run(
              "UPDATE cart_item SET quantity = ? WHERE cart_id = ? AND product_id = ?",
              [newQuantity, cartId, productId],
              (err) => {
                if (err) {
                  db.run("ROLLBACK;");
                  return res.status(500).send("Database error updating cart item.");
                }
                db.run("COMMIT;");
                res.redirect("/");
              }
            );
          } else {
            // If item does not exist, insert it as a new entry
            db.run(
              "INSERT INTO cart_item (cart_id, product_id, quantity) VALUES (?, ?, ?)",
              [cartId, productId, quantityToAdd],
              (err) => {
                if (err) {
                  db.run("ROLLBACK;");
                  return res.status(500).send("Database error inserting new cart item.");
                }
                db.run("COMMIT;");
                res.redirect("/");
              }
            );
          }
        }
      );
    }
  });
});

app.post("/place-order", async (req, res) => {
  const username = req.cookies.username;
  if (!username) {
    return res.status(401).json({ message: "You must be logged in to place an order." });
  }

  db.serialize(() => {
    db.run("BEGIN TRANSACTION;");

    db.get("SELECT id FROM customers WHERE name = ?", [username], (err, customer) => {
      if (err) {
        return res.status(500).json({ message: "Database error while finding the customer." });
      }
      if (!customer) {
        return res.status(404).json({ message: "Customer not found." });
      }

      const customerId = customer.id;

      db.get("SELECT id FROM cart WHERE customer_id = ?", [customerId], (err, cart) => {
        if (err || !cart) {
          db.run("ROLLBACK;");
          return res.status(500).json({ message: "Error finding cart." });
        }

        const cartId = cart.id;

        db.all(
          "SELECT product_id, quantity FROM cart_item WHERE cart_id = ?", [cartId],
          (err, cartItems) => {
            if (err) {
              db.run("ROLLBACK;");
              return res.status(500).json({ message: "Database error while selecting cart items." });
            }

            db.run("INSERT INTO orders (customer_id) VALUES (?)", [customerId], function (err) {
              if (err) {
                db.run("ROLLBACK;");
                return res.status(500).json({ message: "Database error while inserting order." });
              }

              const orderId = this.lastID;

              const insertPromises = cartItems.map(item =>
                new Promise((resolve, reject) => {
                  db.run(
                    "INSERT INTO order_item (order_id, product_id, quantity) VALUES (?, ?, ?)",
                    [orderId, item.product_id, item.quantity],
                    (err) => (err ? reject(err) : resolve())
                  );
                })
              );

              Promise.all(insertPromises).then(() => {
                db.run("DELETE FROM cart_item WHERE cart_id = ?", [cartId], (err) => {
                  if (err) {
                    db.run("ROLLBACK;");
                    return res.status(500).json({ message: "Error clearing cart items." });
                  }
                  db.run("DELETE FROM cart WHERE id = ?", [cartId], (err) => {
                    if (err) {
                      db.run("ROLLBACK;");
                      return res.status(500).json({ message: "Error deleting cart." });
                    }
                    db.run("COMMIT;");
                    res.json({ message: "Order placed successfully!" });
                  });
                });
              }).catch((error) => {
                db.run("ROLLBACK;");
                res.status(500).json({ message: "Error processing the order: " + error });
              });
            });
          }
        );
      });
    });
  });
});


app.post("/update-cart", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg;
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8");
  const formData = JSON.parse(decryptedMessageString);
  console.log("decryptedMessageString: ", decryptedMessageString);
  console.log("FormData: ", formData);
  const username = req.cookies.username;

  if (!username) {
    return res.redirect("/login");
  }


  db.get(
    "SELECT id FROM customers WHERE name = ?",
    [username],
    (err, customer) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).send("Internal server error");
      }

      if (!customer) {
        return res.status(404).send("Customer not found.");
      }

      const updatePromises = [];
      const deletePromises = [];
      var ok = 0;
      Object.keys(formData).forEach(async (key) => {
        const [action, productId] = key.split("_");
        if (action === "quantity") {
          const quantity = parseInt(formData[key]);

          if (!isNaN(quantity) && quantity > 0) {
            db.get("SELECT id FROM cart WHERE customer_id = ?", [customer.id], (err, cart) => {
              if (err) {
                console.error("Error retrieving cart id:", err);
                return;
              }

              if (cart) {
                const updateCartItemAndStock = (db, cartId, productId, requestedQuantity, customerId) => {
                  return new Promise((resolve, reject) => {


                    db.get(`
                                        SELECT ci.quantity AS currentQuantity, p.stoc AS currentStock
                                        FROM cart_item ci
                                        JOIN produse p ON ci.product_id = p.id
                                        WHERE ci.cart_id = ? AND ci.product_id = ?
                                    `, [cartId, productId], (err, row) => {
                      if (err) {
                        if (ok == 0) {
                          ok = 1;
                          db.run('ROLLBACK;');
                        }

                        return reject("Error fetching current quantities");
                      }

                      const { currentQuantity, currentStock } = row;
                      let newStock;

                      if (requestedQuantity > currentQuantity) {
                        newStock = currentStock - (requestedQuantity - currentQuantity);
                        if (newStock < 0) {
                          if (ok == 0) {
                            ok = 1;
                            db.run('ROLLBACK;');
                          }
                          return reject("There is not enough stock available");
                        }
                      } else {
                        newStock = currentStock + (currentQuantity - requestedQuantity);
                      }

                      db.run(`
                                            UPDATE produse
                                            SET stoc = ?
                                            WHERE id = ?
                                        `, [newStock, productId], (err) => {
                        if (err) {
                          if (ok == 0) {
                            ok = 1;
                            db.run('ROLLBACK;');
                          }
                          return reject("Error updating stock");
                        }

                        db.run(`
                                                UPDATE cart_item
                                                SET quantity = ?
                                                WHERE cart_id = ? AND product_id = ?
                                            `, [requestedQuantity, cartId, productId], (err) => {
                          if (err) {
                            if (ok == 0) {
                              ok = 1;
                              db.run('ROLLBACK;');
                            }
                            return reject("Error updating cart item");
                          }


                          resolve();

                        });
                      });
                    });

                  });
                };

                updatePromises.push(updateCartItemAndStock(db, cart.id, parseInt(productId), quantity, customer.id)
                  .catch((error) => {
                    console.error("Error updating stock or cart item:", error);
                  }));

              }
            });
          }
        } else if (action === "delete") {
          deletePromises.push(new Promise((resolve, reject) => {
            db.get(`SELECT quantity
                            FROM cart_item
                            WHERE cart_id IN (SELECT id FROM cart WHERE customer_id = ?) AND product_id = ?
                        `, [customer.id, parseInt(productId)], (err, result) => {
              if (err) {
                db.run('ROLLBACK;');
                return reject("Error fetching current quantity");
              }
              const { quantity } = result;

              db.run(`
                                UPDATE produse
                                SET stoc = stoc + ?
                                WHERE id = ?
                            `, [quantity, parseInt(productId)], (err) => {
                if (err) {
                  db.run('ROLLBACK;');
                  return reject("Error updating stock");
                }

                db.run(`
                                    DELETE FROM cart_item
                                    WHERE cart_id IN (SELECT id FROM cart WHERE customer_id = ?) AND product_id = ?
                                `, [customer.id, parseInt(productId)], (err) => {
                  if (err) {
                    db.run('ROLLBACK;');
                    return reject("Error deleting cart item");
                  }
                  resolve();
                });
              });
            });

          }));
        }
      });
      db.run('BEGIN TRANSACTION;', (err) => {
        if (err) return reject("Error starting transaction");

        Promise.all([...updatePromises, ...deletePromises])
          .then(() => {
            if (ok == 0) {
              db.run('COMMIT;', (err) => {
                if (err) {
                  db.run('ROLLBACK;');
                }
              });
            }

          })
          .then(() => {
            res.redirect("/vizualizare-cos");
          })
          .catch((error) => {
            console.error("Error updating cart:", error);
            db.run('ROLLBACK;');

            res.status(500).send(error);
          });

      });


    }
  );
});
app.get("/vizualizare-cos", (req, res) => {
  const username = req.cookies.username;

  if (!username) {
    return res.redirect("/login");
  }


  db.get(
    "SELECT id FROM customers WHERE name = ?",
    [username],
    (err, customer) => {
      if (err) throw err;

      if (customer) {
        db.all(
          `SELECT ci.product_id, ci.quantity, p.nume, p.pret FROM cart_item ci
         JOIN produse p ON ci.product_id = p.id
         WHERE ci.cart_id IN (SELECT id FROM cart WHERE customer_id = ?)`,
          [customer.id],
          (err, cartItems) => {
            if (err) throw err;

            if (cartItems.length === 0) {
              return res.render("vizualizare-cos", { cart: [], total: 0 });
            }

            let total = 0;
            cartItems.forEach((item) => {
              total += item.pret * item.quantity;
            });

            res.render("vizualizare-cos", {
              cart: cartItems,
              total: total.toFixed(2),
            });
          }
        );
      } else {
        res.status(404).send("Customer not found.");
      }
    }
  );
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

app.post("/verificare-autentificare", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }
  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");
  console.log("ciphertext: ", ciphertext);
  console.log("ivBuffer: ", ivBuffer);
  console.log("tagBuffer: ", tagBuffer);

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const { username, password } = JSON.parse(decryptedMessageString); // Parse JSON string

  const user = users.find((user) => user.utilizator === username);

  if (user) {
    const isMatch = await bcrypt.compare(password, user.parola); // Compare the password with the hashed password

    if (isMatch) {
      console.log("Login successful!");
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
          const blockDuration = 10000; // Block duration in milliseconds (10 seconds)
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
        const blockDuration = 10000;
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
app.post("/inregistrare", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }
  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");
  console.log("ciphertext: ", ciphertext);
  console.log("ivBuffer: ", ivBuffer);
  console.log("tagBuffer: ", tagBuffer);
  // Decrypt using C++ program
  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const { username, password } = JSON.parse(decryptedMessageString); // Parse JSON string

  // Check if the username already exists
  const userExists = users.some((user) => user.utilizator === username);
  if (userExists) {
    return res.render("inregistrare", {
      errorMessage: "Username already exists. Please choose another one.",
    });
  }
  // Hash the password
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  // Add new user with admin set to false
  const newUser = {
    utilizator: username,
    parola: hashedPassword,
    admin: false,
  };
  users.push(newUser);

  // Save the updated user list back to the file
  fs.writeFile("utilizatori.json", JSON.stringify(users, null, 2), (err) => {
    if (err) {
      console.error("Error saving user data:", err);
      return res.status(500).send("Internal Server Error");
    }
  });
  // Insert the new user into the customers table
  db.run("INSERT INTO customers (name) VALUES (?)", [username], (err) => {
    if (err) {
      console.error("Error adding customer to the database:", err);
      return res.status(500).send("Internal Server Error");
    }

    console.log("Customer added to database:", username);

    res.redirect("/autentificare");
  });
});

app.get("/upload_file", (req, res) => {
  res.render("upload_file");
});
app.get("/chestionar", (req, res) => {
  const fs = require("fs");

  // Read the contents of the JSON file
  const intrebariData = fs.readFileSync("intrebari.json");
  const listaIntrebari = JSON.parse(intrebariData);
  res.render("chestionar", { intrebari: listaIntrebari });
});
app.post("/rezultat-chestionar", (req, res) => {
  const intrebariData = fs.readFileSync("intrebari.json");
  const intrebari = JSON.parse(intrebariData);

  const raspunsuri = [];
  for (let i = 0; i < intrebari.length; i++) {
    const answer = req.body[`raspuns${i}`];

    if (answer) {
      raspunsuri.push(answer[0]); // If answer exists, push it to raspunsuri array
    } else {
      raspunsuri.push(null); // If no answer, push null 
    }
  }

  const variante = intrebari.map((intrebare) => intrebare.variante[0]);

  console.log(intrebari, variante, raspunsuri);
  res.render("rezultat-chestionar", { intrebari, variante, req, raspunsuri });
});

app.get("/admin", (req, res) => {
  const admin = req.cookies.admin === "true";
  db.all("SELECT * FROM produse", [], (err, products) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Internal Server Error");
    }
    res.render("admin", { products });
  });
});
app.post("/admin/adauga-produs", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const formData = JSON.parse(decryptedMessageString); // Parse the form data
  console.log("FormData: ", formData);
  const { nume, pret, stoc } = formData;

  db.run(
    "INSERT INTO produse (nume, pret, stoc) VALUES (?, ?, ?)",
    [nume, pret, stoc],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Internal Server Error");
      }
      res.json({ message: "Product added successfully!" });
    }
  );
});
app.post("/admin/update-stoc", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const formData = JSON.parse(decryptedMessageString); // Parse the form data
  const { id, stoc } = formData;

  db.run("UPDATE produse SET stoc = ? WHERE id = ?", [stoc, id], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Internal Server Error");
    }
    res.json({ message: "Stock updated successfully!" });
  });
});
app.post("/admin/delete-produs", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const formData = JSON.parse(decryptedMessageString); // Parse the form data
  const { id } = formData;

  db.run("DELETE FROM produse WHERE id = ?", [id], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Internal Server Error");
    }
    res.json({ message: "Product deleted successfully!" });
  });
});
app.post("/admin/update-pret", async (req, res) => {
  const { encryptedData, iv, tag } = req.body;

  console.log("encryptedData: ", encryptedData);
  console.log("iv: ", iv);
  console.log("tag: ", tag);

  if (!encryptedData || !iv || !tag) {
    return res.status(400).json({ message: "Invalid encrypted input." });
  }

  const ciphertext = Buffer.from(encryptedData, "base64");
  const ivBuffer = Buffer.from(iv, "base64");
  const tagBuffer = Buffer.from(tag, "base64");
  const aesKey = Buffer.from(req.session.aesKey, "hex");

  const decrypted = await decryptAESWithCPP(
    ciphertext,
    aesKey,
    "",
    ivBuffer,
    tagBuffer
  );

  const decryptedMessageBuffer = decrypted.encryptedmsg; // Extract the Buffer
  const decryptedMessageString = decryptedMessageBuffer.toString("utf-8"); // Convert Buffer to string
  const formData = JSON.parse(decryptedMessageString); // Parse the form data
  const { id, pret } = formData;

  db.run("UPDATE produse SET pret = ? WHERE id = ?", [pret, id], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Internal Server Error");
    }
    res.json({ message: "Price updated successfully!" });
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
