# AES_Lib.py
from Crypto.Cipher import AES
from Crypto.Util import Counter
import numpy as np
import os

class AES_Software:
    def __init__(self, key_bytes):
        """
        Khởi tạo AES-256 chế độ CTR (Counter Mode).
        CTR được chọn vì nó cho phép xử lý song song (tốt cho tư duy FPGA sau này).
        """
        if len(key_bytes) != 32:
            raise ValueError("AES-256 yêu cầu khóa 32 bytes (256 bits).")
        self.key = key_bytes
        # # Tạo nonce cố định cho demo (trong thực tế cần random)
        # self.nonce = b'\x00' * 8
        self.nonce = os.urandom(8)  # Thay đổi nonce cho mỗi phiên mã hóa trong thực tế/ Random mỗi lần  
 
    def encrypt_image(self, image_array):
        """
        Mã hóa ảnh (numpy array)
        """
        # 1. Chuyển ảnh thành chuỗi bytes
        img_bytes = image_array.tobytes()
        
        # 2. Khởi tạo Cipher
        # Counter mode không cần padding, giữ nguyên kích thước dữ liệu
        ctr = Counter.new(64, prefix=self.nonce, initial_value=0)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        
        # 3. Mã hóa
        encrypted_bytes = cipher.encrypt(img_bytes)
        return encrypted_bytes

    def decrypt_to_image(self, encrypted_bytes, shape, dtype):
        """
        Giải mã bytes thành ảnh
        Args:
            shape: Kích thước gốc của ảnh (H, W, C)
            dtype: Kiểu dữ liệu gốc (thường là uint8)
        """
        # 1. Khởi tạo Cipher (cùng nonce và counter)
        ctr = Counter.new(64, prefix=self.nonce, initial_value=0)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        
        # 2. Giải mã
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        
        # 3. Reshape lại thành numpy array để hiển thị
        decrypted_img = np.frombuffer(decrypted_bytes, dtype=dtype).reshape(shape)
        return decrypted_img