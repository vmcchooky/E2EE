# crypto_utils.py
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Import mới cho GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Các hàm RSA (Dùng ngay bây giờ) ---

def load_public_key_from_bytes(key_bytes):
    """Nạp một đối tượng public key từ dữ liệu bytes (PEM format)."""
    return serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )

def rsa_encrypt(data, public_key_obj):
    """Mã hóa dữ liệu bằng một đối tượng public key RSA."""
    encrypted_data = public_key_obj.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def rsa_decrypt(encrypted_data, private_key_obj):
    """Giải mã dữ liệu bằng một đối tượng private key RSA."""
    decrypted_data = private_key_obj.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data


def generate_aes_key():
    """
    Tạo khóa AES-GCM.
    AESGCM hỗ trợ khóa 128, 192, hoặc 256 bits.
    Ta dùng 256 bits (32 bytes) cho an toàn nhất.
    """
    return AESGCM.generate_key(bit_length=256)

def aes_encrypt(data_bytes, key):
    """
    Mã hóa dữ liệu bằng AES-GCM.
    Input: data (bytes), key (bytes)
    Output: Nonce + Ciphertext + Tag (đã gộp chung)
    """
    try:
        # 1. Khởi tạo đối tượng AESGCM với khóa
        aesgcm = AESGCM(key)
        
        # 2. Tạo Nonce (tương tự IV) - GCM bắt buộc Nonce phải là DUY NHẤT cho mỗi lần mã hóa
        # Kích thước chuẩn của Nonce cho GCM là 12 bytes
        nonce = os.urandom(12)
        
        # 3. Mã hóa
        # Hàm encrypt của AESGCM tự động tính toán Tag xác thực và gắn vào cuối ciphertext
        ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data=None)
        
        # 4. Trả về Nonce + Ciphertext (để bên nhận có thể giải mã)
        return nonce + ciphertext
    except Exception as e:
        print(f"Lỗi mã hóa GCM: {e}")
        return None

def aes_decrypt(encrypted_data, key):
    """
    Giải mã dữ liệu AES-GCM.
    Input: encrypted_data (Nonce + Ciphertext + Tag), key
    Output: Plaintext (bytes) hoặc None nếu xác thực thất bại
    """
    try:
        # 1. Tách Nonce (12 bytes đầu)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # 2. Khởi tạo đối tượng
        aesgcm = AESGCM(key)
        
        # 3. Giải mã & Xác thực
        # Nếu dữ liệu bị thay đổi dù chỉ 1 bit, hàm này sẽ ném ra lỗi InvalidTag
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        
        return plaintext
    except Exception as e:
        print(f"Lỗi giải mã GCM (có thể do sai khóa hoặc dữ liệu bị giả mạo): {e}")
        return None
    
def generate_or_load_keys(name: str, password: str):
    """Tạo hoặc nạp cặp khóa RSA được bảo vệ bằng password.

    - Nếu file chưa tồn tại: tạo mới, MÃ HÓA private key bằng password.
    - Nếu file đã tồn tại: yêu cầu đúng password để giải mã.
    """
    private_key_file = f"Keys/Private/private_key_{name}.pem"
    public_key_file = f"Keys/Public/public_key_{name}.pem"

    private_key = None
    public_key_bytes = None

    if not password:
        print("Loi: password bao ve private key khong duoc rong.")
        return None, None

    try:
        if os.path.exists(private_key_file):
            print("Dang nap khoa cu (protected by password)...")
            with open(private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode("utf-8"),
                    backend=default_backend()
                )

            with open(public_key_file, "rb") as f:
                public_key_bytes = f.read()
                # Kiểm tra xem public key có hợp lệ không
                serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

            print("Nap khoa thanh cong.")
        else:
            print("Dang tao cap khoa RSA moi (co the mat vai giay)...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Lưu private key ĐƯỢC MÃ HÓA bằng password
            with open(private_key_file, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(
                            password.encode("utf-8")
                        ),
                    )
                )

            # Lưu public key như cũ
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(public_key_file, "wb") as f:
                f.write(public_key_bytes)

            print(f"Da tao va luu khoa vao {private_key_file} va {public_key_file}.")

        return private_key, public_key_bytes

    except Exception as e:  # noqa: BLE001
        print(f"Loi khi xu ly khoa (co the do sai password): {e}")
        return None, None
# END OF FILE
