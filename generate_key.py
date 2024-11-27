from cryptography.fernet import Fernet

# Generar una nueva clave
key = Fernet.generate_key()

# Guardar la clave en un archivo para su uso posterior
with open("secret.key", "wb") as key_file:
    key_file.write(key)

# Imprimir la clave generada para referencia
print("Clave generada:", key)
