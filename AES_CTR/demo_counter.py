# demo_counter.py
# Minh họa cách Counter Generator hoạt động trong CTR Mode

from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

def demo_counter_generator():
    """
    Minh họa chi tiết Counter Generator
    """
    print("="*60)
    print("DEMO: Counter Generator trong AES-CTR Mode")
    print("="*60)
    
    # 1. Tạo key và nonce
    key = b'0123456789ABCDEF' * 2  # 32 bytes cho AES-256
    nonce = b'\x12\x34\x56\x78\x90\xAB\xCD\xEF'  # 8 bytes = 64 bits
    
    print(f"\n🔑 Key (256-bit): {key.hex()}")
    print(f"🎲 Nonce (64-bit): {nonce.hex()}")
    
    # 2. Tạo Counter Generator
    print("\n" + "─"*60)
    print("📊 COUNTER GENERATOR:")
    print("─"*60)
    
    ctr = Counter.new(
        64,                    # Counter là 64 bits
        prefix=nonce,          # Nonce 64 bits ở đầu
        initial_value=0        # Bắt đầu từ 0
    )
    
    print(f"• Counter size: 64 bits")
    print(f"• Prefix (Nonce): {nonce.hex()}")
    print(f"• Initial value: 0")
    print(f"• Total block size: 128 bits (64-bit nonce + 64-bit counter)")
    
    # 3. Minh họa mã hóa nhiều blocks
    print("\n" + "─"*60)
    print("🔐 MÃ HÓA CÁC BLOCKS:")
    print("─"*60)
    
    # Giả lập dữ liệu ảnh (3 blocks = 48 bytes)
    plaintext_blocks = [
        b'Block_0_Data_16B',  # 16 bytes = 128 bits (1 AES block)
        b'Block_1_Data_16B',
        b'Block_2_Data_16B'
    ]
    
    # Mã hóa từng block để thấy rõ counter tăng
    for i, block in enumerate(plaintext_blocks):
        # Tạo counter mới cho mỗi block (để demo)
        ctr_demo = Counter.new(64, prefix=nonce, initial_value=i)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr_demo)
        
        # Mã hóa
        encrypted = cipher.encrypt(block)
        
        print(f"\nBlock {i}:")
        print(f"  Counter Value: {i}")
        print(f"  Counter Block: [Nonce: {nonce.hex()}][Counter: {i:016x}]")
        print(f"  Plaintext:  {block.decode()}")
        print(f"  Ciphertext: {encrypted.hex()}")
    
    # 4. So sánh: mã hóa liên tục vs từng block
    print("\n" + "="*60)
    print("🔄 SO SÁNH: Mã hóa liên tục vs từng block")
    print("="*60)
    
    # Mã hóa liên tục (cách thực tế)
    ctr_continuous = Counter.new(64, prefix=nonce, initial_value=0)
    cipher_continuous = AES.new(key, AES.MODE_CTR, counter=ctr_continuous)
    all_data = b''.join(plaintext_blocks)
    encrypted_continuous = cipher_continuous.encrypt(all_data)
    
    # Mã hóa từng block
    ctr_separate = Counter.new(64, prefix=nonce, initial_value=0)
    cipher_separate = AES.new(key, AES.MODE_CTR, counter=ctr_separate)
    encrypted_separate = b''.join([cipher_separate.encrypt(b) for b in plaintext_blocks])
    
    print(f"\n✓ Mã hóa liên tục: {encrypted_continuous.hex()}")
    print(f"✓ Mã hóa từng block: {encrypted_separate.hex()}")
    print(f"✓ Giống nhau? {encrypted_continuous == encrypted_separate}")
    
    # 5. Demo song song hóa (parallel processing)
    print("\n" + "="*60)
    print("⚡ PARALLEL PROCESSING - Ưu điểm cho FPGA")
    print("="*60)
    
    print("\n💡 Vì Counter độc lập, có thể mã hóa song song:")
    for i in range(5):
        print(f"  Core {i}: [Nonce: {nonce.hex()}][Counter: {i:016x}] → AES → KeyStream_{i}")
    
    print("\n✨ Trên FPGA:")
    print("  • Có thể tạo nhiều AES core song song")
    print("  • Mỗi core xử lý 1 counter value")
    print("  • Throughput tăng tuyến tính theo số core")
    print("  • Không phải đợi block trước (khác CBC)")

def demo_counter_overflow():
    """
    Demo trường hợp counter overflow (vượt quá 2^64)
    """
    print("\n" + "="*60)
    print("⚠️  COUNTER OVERFLOW - Giới hạn của CTR Mode")
    print("="*60)
    
    # Counter 64-bit có thể đếm đến 2^64 - 1
    max_blocks = 2**64
    block_size = 16  # bytes
    max_data_size = max_blocks * block_size
    
    print(f"\n📏 Với 64-bit counter:")
    print(f"  • Số blocks tối đa: {max_blocks:,} blocks")
    print(f"  • Dung lượng tối đa: {max_data_size:,} bytes")
    print(f"  • = {max_data_size / (1024**4):.2f} TB")
    print(f"  • = {max_data_size / (1024**5):.2f} PB")
    print(f"\n💡 Đủ cho hầu hết ứng dụng thực tế!")
    print(f"   (Với ảnh 4K, video 8K đều không vấn đề)")

if __name__ == "__main__":
    demo_counter_generator()
    demo_counter_overflow()
    
    print("\n" + "="*60)
    print("✅ DEMO HOÀN TẤT")
    print("="*60)
