
# Hybrid Encrypted Communication Server

## Overview
This project is a **fully encrypted online beverage store** built with **Node.js** and powered by **end-to-end encryption** for secure communication. It implements a **hybrid encryption system**, utilizing **RSA for key exchange** and **AES-GCM for data encryption**.



## Security Architecture
- **Key Exchange:** Secure **RSA handshake** to establish a shared symmetric key.  
- **Symmetric Encryption (Post-Handshake):**  
  - **Client → Server:** Encrypts data using the browser’s **Web Crypto API (AES-GCM)** before transmission.  
  - **Server → Client:** Encrypts responses using a **custom C++ AES-GCM implementation**.  
- **Password Protection:** Securely **hashed and stored**, ensuring user credentials remain safe.

## Features
- 🔒 **End-to-End Encryption:** All transmitted data is encrypted using a secure **RSA + AES-GCM** pipeline.  
- 🛍 **Fully Functional Beverage Store:** Users can browse, add items to cart, and check out.  
- 👤 **User Authentication:** Secure login.  
- 📊 **Performance Benchmarking:** Compares the custom AES-GCM implementation with OpenSSL.  



## Node.js Beverage Store Website

Welcome to the Node.js Store Website! This dynamic application replicates a beverage store experience, built with Node.js for efficient server-side execution and interaction with a SQLite3 database. Explore its key features and components:

### Features

- **User-Friendly Interface:** Seamless browsing experience with a diverse selection of beverages.
- **Beverage Questionnaire:** Tailor your experience with a user-friendly preferences survey.
- **Spam Protection Middleware:** Secure login process with anti-spam measures.
- **Resource Not Found Handling:** Maintain stability by handling non-existent resource access.
- **Admin Control:** Authorized admins manage inventory by adding new items.
- **Personalized User Page:** Manage cart, update quantities, and proceed to checkout.





## Getting Started

1. **Clone the Repository:**
2. **Install Dependencies:** `npm install`
3. **Database Setup:** `npm run db:setup`
4. **Start the Server:** `nodemon app.js`
5. **Explore:** Open `http://localhost:6789` in your browser.
