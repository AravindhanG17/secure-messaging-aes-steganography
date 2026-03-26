# Secure Messaging AES Steganography Project Overview



This project is a Dual-Layer Secure Messaging System that combines AES encryption with image-based steganography to ensure secure communication. Messages can be encrypted, hidden inside images, and protected with advanced security features such as burn-after-view, screenshot protection, and a Deadman switch.



## Features

* AES Encryption for secure message confidentiality
* Image-based Steganography for hidden communication
* Message Integrity Verification using hashing
* Burn-after-view messages
* Screenshot protection and monitoring
* Deadman Switch emergency system
* Token-based secure message access
* Message read/delivery tracking
* Scheduled message unlock



## Technologies Used

* Python
* Flask / FastAPI
* MySQL
* HTML, CSS, JavaScript
* AES Cryptography
* Steganography Techniques
* Git and GitHub



## Database Tables

* users
* messages
* conversation\_reads
* deadman\_settings
* deadman\_events
* key\_access\_tokens
* screenshot\_events
* user\_preferences



## Installation

1. Clone the repository
2. Install dependencies: pip install -r requirements.txt
3. Setup MySQL database
4. Run the application: python app.py



## Usage

* Register a new user
* Send encrypted messages
* Hide messages inside images
* Receive and decrypt messages securely
* Use the advanced security features



## Future Enhancements

* Mobile application support
* Multi-factor authentication
* Cloud deployment
* Enhanced monitoring dashboard

