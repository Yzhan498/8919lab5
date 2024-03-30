from azure.identity import DefaultAzureCredential
from azure.keyvault.keys.crypto import CryptographyClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.secrets import SecretClient
import base64

# Replace these values with your Azure Key Vault details
key_vault_name = "zhan0865keyvault"
key_name = "zhan0865key"
key_version = "0812eb08f5c9457d87222126e492d8d2"
secret_name = "zhan0865secret"

# Initialize the Key Vault clients
credential = DefaultAzureCredential()
key_client = KeyClient(vault_url=f"https://{key_vault_name}.vault.azure.net/", credential=credential)
secret_client = SecretClient(vault_url=f"https://{key_vault_name}.vault.azure.net/", credential=credential)
key = key_client.get_key(key_name, key_version)

try:
    # Initialize the Cryptography client
    crypto_client = CryptographyClient(key, credential=credential)
    print("Cryptography client initialized successfully.")
except Exception as e:
    print("Error occurred during initialization:", e)

# Get user input for data to encrypt
plaintext = input("Enter data to encrypt and store as secret: ")

# Encrypt the data
cipher_text = crypto_client.encrypt(plaintext.encode())

# Display encrypt cipher data
print("ciphertext:", cipher_text)

# Convert the encrypted data to base64 for storage
encrypted_data_base64 = base64.b64encode(cipher_text.ciphertext).decode('utf-8')

# Store the encrypted data as a secret in Azure Key Vault
secret_client.set_secret(secret_name, encrypted_data_base64)

# Print confirmation message
print("Encrypted data stored as secret successfully.")
# Fetch the encryption key using its identifier
secret = secret_client.get_secret(secret_name)
# key_id = secret.properties.key_id
# key = key_client.get_key_from_key_id(key_id)
key = key_client.get_key(key_name, key_version)
# Initialize the Cryptography client with the fetched key
crypto_client = CryptographyClient(key, credential=credential)

# Retrieve the encrypted data (secret) from Azure Key Vault
encrypted_data_base64 = secret_client.get_secret(secret_name).value
encrypted_data = base64.b64decode(encrypted_data_base64)

# Decrypt the encrypted data using the encryption key
decrypted_data = crypto_client.decrypt(encrypted_data)

# Display the original string to the user
print("Original data:", decrypted_data.decode('utf-8'))