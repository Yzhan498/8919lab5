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
print("Plaintext:", plaintext)

# Encrypt the data
encrypt_result = crypto_client.encrypt("RSA1_5",plaintext.encode())

# Display encrypt cipher data
print("ciphertext:", encrypt_result.ciphertext)

# Convert the encrypted data to base64 for storage
encrypted_data_base64 = base64.b64encode(encrypt_result.ciphertext).decode('utf-8')

# Store the encrypted data as a secret in Azure Key Vault
secret_client.set_secret(secret_name, encrypted_data_base64)

# Print confirmation message
print("Encrypted data stored as secret successfully.",secret_name,secret_client,SecretClient.get_secret)

# Retrieve the encrypted data (secret) from Azure Key Vault
secret = secret_client.get_secret(secret_name)
encrypted_data_base64 = secret.value  # Retrieve the secret value

# Convert the base64-encoded encrypted data to bytes
encrypted_data = base64.b64decode(encrypted_data_base64)

# Decrypt the encrypted data using the encryption key
decrypt_result = crypto_client.decrypt("RSA1_5",encrypted_data)

# Display the original string to the user
print("Original data:", decrypt_result.plaintext.decode('utf-8'))

