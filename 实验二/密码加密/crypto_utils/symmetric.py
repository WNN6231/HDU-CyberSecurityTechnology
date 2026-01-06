import base64
import os
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm4

class SymmetricCrypto:
    """对称加密类，支持SM4、AES、3DES"""
    
    def __init__(self):
        self.algorithms = ['SM4', 'AES', '3DES']
    
    def generate_key(self, algorithm='SM4'):
        """生成对称密钥"""
        if algorithm == 'SM4':
            return get_random_bytes(16)  # SM4密钥长度为128位
        elif algorithm == 'AES':
            return get_random_bytes(32)  # AES-256
        elif algorithm == '3DES':
            return get_random_bytes(24)  # 3DES密钥长度为192位
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
    
    def encrypt(self, plaintext, key, algorithm='SM4'):
        """加密函数"""
        if not plaintext:
            return ""
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        try:
            if algorithm == 'SM4':
                return self._encrypt_sm4(plaintext, key)
            elif algorithm == 'AES':
                return self._encrypt_aes(plaintext, key)
            elif algorithm == '3DES':
                return self._encrypt_3des(plaintext, key)
            else:
                raise ValueError(f"不支持的算法: {algorithm}")
        except Exception as e:
            raise Exception(f"{algorithm}加密失败: {str(e)}")
    
    def decrypt(self, ciphertext, key, algorithm='SM4'):
        """解密函数"""
        if not ciphertext:
            return ""
        
        try:
            if algorithm == 'SM4':
                return self._decrypt_sm4(ciphertext, key)
            elif algorithm == 'AES':
                return self._decrypt_aes(ciphertext, key)
            elif algorithm == '3DES':
                return self._decrypt_3des(ciphertext, key)
            else:
                raise ValueError(f"不支持的算法: {algorithm}")
        except Exception as e:
            raise Exception(f"{algorithm}解密失败: {str(e)}")
    
    def _encrypt_sm4(self, plaintext, key):
        """SM4加密"""
        sm4_cipher = CryptSM4()
        sm4_cipher.set_key(key, SM4_ENCRYPT)
        
        # 填充数据
        padded_data = pad(plaintext, 16)
        
        # 加密
        ciphertext = sm4_cipher.crypt_ecb(padded_data)
        
        # Base64编码
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def _decrypt_sm4(self, ciphertext, key):
        """SM4解密"""
        if not ciphertext:
            return ""
        
        try:
            # Base64解码
            ciphertext_bytes = base64.b64decode(ciphertext)
        except Exception as e:
            raise Exception(f"Base64解码失败: {str(e)}")
        
        if len(ciphertext_bytes) == 0:
            return ""
        
        try:
            sm4_cipher = CryptSM4()
            sm4_cipher.set_key(key, SM4_DECRYPT)
            
            # 解密
            padded_data = sm4_cipher.crypt_ecb(ciphertext_bytes)
            
            if len(padded_data) == 0:
                return ""
            
            # 去除填充
            plaintext = unpad(padded_data, 16)
            return plaintext.decode('utf-8')
        except Exception as e:
            # 如果去填充失败，尝试直接返回解密数据
            try:
                return padded_data.decode('utf-8', errors='replace')
            except:
                raise Exception(f"SM4解密失败: {str(e)}")
    
    def _encrypt_aes(self, plaintext, key):
        """AES加密"""
        cipher = AES.new(key, AES.MODE_CBC)
        
        # 填充数据
        padded_data = pad(plaintext, AES.block_size)
        
        # 加密
        ciphertext = cipher.encrypt(padded_data)
        
        # 组合IV和密文，然后进行Base64编码
        encrypted_data = cipher.iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def _decrypt_aes(self, ciphertext, key):
        """AES解密"""
        if not ciphertext:
            return ""
        
        try:
            # Base64解码
            encrypted_data = base64.b64decode(ciphertext)
        except Exception as e:
            raise Exception(f"Base64解码失败: {str(e)}")
        
        if len(encrypted_data) < AES.block_size:
            return ""
        
        try:
            # 提取IV和密文
            iv = encrypted_data[:AES.block_size]
            ciphertext_bytes = encrypted_data[AES.block_size:]
            
            if len(ciphertext_bytes) == 0:
                return ""
            
            # 解密
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = cipher.decrypt(ciphertext_bytes)
            
            if len(padded_data) == 0:
                return ""
            
            # 去除填充
            plaintext = unpad(padded_data, AES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            # 如果去填充失败，尝试直接返回解密数据
            try:
                return padded_data.decode('utf-8', errors='replace')
            except:
                raise Exception(f"AES解密失败: {str(e)}")
    
    def _encrypt_3des(self, plaintext, key):
        """3DES加密"""
        cipher = DES3.new(key, DES3.MODE_CBC)
        
        # 填充数据
        padded_data = pad(plaintext, DES3.block_size)
        
        # 加密
        ciphertext = cipher.encrypt(padded_data)
        
        # 组合IV和密文，然后进行Base64编码
        encrypted_data = cipher.iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def _decrypt_3des(self, ciphertext, key):
        """3DES解密"""
        if not ciphertext:
            return ""
        
        try:
            # Base64解码
            encrypted_data = base64.b64decode(ciphertext)
        except Exception as e:
            raise Exception(f"Base64解码失败: {str(e)}")
        
        if len(encrypted_data) < DES3.block_size:
            return ""
        
        try:
            # 提取IV和密文
            iv = encrypted_data[:DES3.block_size]
            ciphertext_bytes = encrypted_data[DES3.block_size:]
            
            if len(ciphertext_bytes) == 0:
                return ""
            
            # 解密
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            padded_data = cipher.decrypt(ciphertext_bytes)
            
            if len(padded_data) == 0:
                return ""
            
            # 去除填充
            plaintext = unpad(padded_data, DES3.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            # 如果去填充失败，尝试直接返回解密数据
            try:
                return padded_data.decode('utf-8', errors='replace')
            except:
                raise Exception(f"3DES解密失败: {str(e)}")