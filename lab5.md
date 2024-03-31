Part 1: Setting Up Azure Key Vault
Create an Azure Key Vault:
Navigate to the Azure CLI and create a new Key Vault.
Follow the instructions to establish a Key Vault, noting down its name, resource group, and region.
![create group resource](<img/Screenshot 2024-03-29 at 4.41.56 PM.png>)
![Create key vault](<img/Screenshot 2024-03-29 at 4.45.54 PM.png>)
Set Access Policies:
Configure access policies to allow your account to manage keys and secrets.
![accessed](<img/Screenshot 2024-03-29 at 5.04.01 PM.png>)
Part 2: Encrypting Data
Create an Encryption Key:
Use Azure Key Vault to generate a new encryption key.
Write down the key identifier (ID).
![create the encryption key](<img/Screenshot 2024-03-29 at 5.16.59 PM.png>)
Write a Program to Encrypt Data:
Choose a programming language and set up the environment for Azure SDK.
Install Azure SDK Libraries
pip install azure-identity  # For Azure Identity library
pip install azure-keyvault-secrets  # For Azure Key Vault Secrets library
pip install azure-keyvault-keys  # For Azure Key Vault Keys library
pip install cryptography  # For cryptography package
![sdk connection](<img/Screenshot 2024-03-31 at 6.08.30 PM.png>)
Write a program that takes a user input string and uses the Azure Key Vault API to encrypt the string with the generated encryption key.
![encrypt code](<img/Screenshot 2024-03-31 at 6.10.27 PM.png>)
The program should display the encrypted data (ciphertext).
![ciphertext](<img/Screenshot 2024-03-31 at 6.12.14 PM.png>)
Part 3: Storing Encrypted Data
Store the Encrypted String:
Using the same program, store the encrypted string as a secret in the Azure Key Vault.
![store code](<img/Screenshot 2024-03-31 at 6.13.29 PM.png>)
The program should output confirmation that the secret is stored, along with its identifier.
![output](<img/Screenshot 2024-03-31 at 6.16.42 PM.png>)
![in Azure](<img/Screenshot 2024-03-31 at 6.34.53 PM.png>)
Part 4: Decrypting Data
Fetch the Encryption Key:
Modify your program to fetch the encryption key from Azure Key Vault using the key identifier.
Decrypt the Encrypted String:
Update the program to retrieve the encrypted string (secret) from Azure Key Vault.
Use the fetched encryption key to decrypt the string.
![retrieve code](<img/Screenshot 2024-03-31 at 6.18.14 PM.png>)
Display the original string to the user, confirming successful decryption.
![original string as same as typing](<img/Screenshot 2024-03-31 at 6.37.58 PM.png>)