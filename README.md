# Project Setup

## 1. Setup venv
python -m venv venv

## 2. activate
|OS | bash Command |
|---|---------|
|mac & linux| source venv/bin/activate |
|windows| .\venv\Scripts\activate|

If you are not allowed to run scripts see this link for a fix:

https://www.stanleyulili.com/powershell/solution-to-running-scripts-is-disabled-on-this-system-error-on-powershell

## 3. install dependencies
pip install -r requirements.txt

## 4. npm
```npm install```

## 5. Run app.py
```python app.py```
and go to ```127.0.0.1:5000```
Premade master password: ```goodPassword```

# Example screenshots
Welcome screen where the user can log in or set a new password which will reset the database.
![billede](https://github.com/user-attachments/assets/0ebc231f-34e6-49e6-ab54-0f1bd5f0d7fc)

Main screen where new logins can be added. Passwords can be generated with the circular arrow button
![billede](https://github.com/user-attachments/assets/dc3c8c10-b953-4146-931b-4a588f043a98)

A login can be selected in the left panel to decrypt and show it on the right side
![billede](https://github.com/user-attachments/assets/21156b8b-78b7-4ba0-907e-83bb0270727b)

# Security
This app uses symmetric encryption, meaning the same key is use to encrypt and decrypt data.
## master password
When the master password is set it is salted and hashed with argon2. 
Before saving the hashed master password, the database it cleared of all old data, since it would be useless to keep data we cannot decrypt anyway.

## Saving logins
First the raw login details are encrypted with an encryption key derrived from the master password and a random salt.
The encrypted login is then saved to the database together with the salt. We need to save the salt so we can generate the same key when it is time to decrypt the data again.

## Retrieving logins
In the left side of the app all the websites are displayed by getting them out of the database and decrypting only the name of the website.
When the user clicks on a website, the full login details will be retrieved from the database and be decrypted by regenerating the correct key using the saved salt and master password

# Considerations
Since this application is local i have no consideration for transfering keys between frontend and backend. 
Instead i have made sure that even if someone gets physical acces to the host pc and database file, it will all be useless without the master password, since all data is encrypted.

A nice expantion to this app would be a timeout so the user has to reauthenticate after 15min, and cannot accidently leave their pc open and vulnerable at the public library.

# Diagrams
## Encryption
![billede](https://github.com/user-attachments/assets/def7d068-f360-4438-9670-1c08cdee7841)

## Decryption
![billede](https://github.com/user-attachments/assets/b3020d77-f8a9-4897-966c-f87e5fa1d143)

#pitfalls 
The password generation method found in static/js/util.js will create a random password from the given charset which is currently set to the standard english keyboard and some special characters. This means anyone with access to the app know what characters to limit their brute force attacks to. This list could be extended to make generated passwords more complex.

The user interface is a website which feels a little wrong for a local program a desktop app would be expected. I did this because i wanted to try out some simple html templating and Htmx


