import base64
import binascii
import os
import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16
NONCE_SIZE = 12
VERSION = b"V1"


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(text: str, password: str) -> str:
    if not text:
        raise ValueError("Digite o texto que deseja criptografar.")
    if not password:
        raise ValueError("Digite uma senha.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    payload = VERSION + salt + nonce + ciphertext
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_text(encoded_text: str, password: str) -> str:
    if not encoded_text:
        raise ValueError("Cole o texto criptografado.")
    if not password:
        raise ValueError("Digite uma senha.")

    try:
        payload = base64.urlsafe_b64decode(encoded_text.strip().encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("O texto criptografado não possui formato válido.") from exc

    minimum_size = len(VERSION) + SALT_SIZE + NONCE_SIZE + 16
    if len(payload) < minimum_size or payload[:len(VERSION)] != VERSION:
        raise ValueError("O texto criptografado não possui formato válido.")

    salt_start = len(VERSION)
    nonce_start = salt_start + SALT_SIZE
    ciphertext_start = nonce_start + NONCE_SIZE
    salt = payload[salt_start:nonce_start]
    nonce = payload[nonce_start:ciphertext_start]
    ciphertext = payload[ciphertext_start:]
    key = derive_key(password, salt)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Senha incorreta ou texto criptografado alterado.") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Os dados descriptografados não são texto UTF-8 válido.") from exc


class CryptoApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Criptografia de Texto")
        self.geometry("720x560")
        self.minsize(620, 500)

        main = ttk.Frame(self, padding=16)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="Senha:").pack(anchor="w")
        self.password = ttk.Entry(main, show="*", width=50)
        self.password.pack(fill="x", pady=(4, 12))

        ttk.Label(main, text="Texto:").pack(anchor="w")
        self.input_text = tk.Text(main, height=10, wrap="word")
        self.input_text.pack(fill="both", expand=True, pady=(4, 12))

        actions = ttk.Frame(main)
        actions.pack(fill="x", pady=(0, 12))
        ttk.Button(actions, text="Criptografar", command=self.encrypt).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Descriptografar", command=self.decrypt).pack(side="left")

        ttk.Label(main, text="Resultado:").pack(anchor="w")
        self.output_text = tk.Text(main, height=8, wrap="word")
        self.output_text.pack(fill="both", expand=True, pady=(4, 12))

        ttk.Button(main, text="Copiar resultado para a área de transferência", command=self.copy_result).pack(fill="x")

    def encrypt(self) -> None:
        try:
            encrypted = encrypt_text(self.input_text.get("1.0", "end-1c"), self.password.get())
            self.output_text.delete("1.0", "tk.END")
            self.output_text.insert("1.0", encrypted)
        except ValueError as exc:
            messagebox.showwarning("Aviso", str(exc))

    def decrypt(self) -> None:
        try:
            decrypted = decrypt_text(self.input_text.get("1.0", "end-1c"), self.password.get())
            self.output_text.delete("1.0", "tk.END")
            self.output_text.insert("1.0", decrypted)
        except ValueError as exc:
            messagebox.showwarning("Não foi possível descriptografar", str(exc))

    def copy_result(self) -> None:
        result = self.output_text.get("1.0", "end-1c")
        if not result:
            messagebox.showwarning("Aviso", "Não há resultado para copiar.")
            return

        self.clipboard_clear()
        self.clipboard_append(result)
        self.update()
        messagebox.showinfo("Copiado", "Resultado copiado para a área de transferência.")


if __name__ == "__main__":
    CryptoApp().mainloop()
