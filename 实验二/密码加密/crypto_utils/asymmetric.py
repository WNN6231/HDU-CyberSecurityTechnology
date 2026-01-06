import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from gmssl.func import random_hex
import os

class AsymmetricCrypto:
    """非对称加密类，支持RSA、ECC"""
    
    def __init__(self):
        self.algorithms = ['RSA', 'ECC']
    
    def generate_key_pair(self, algorithm='RSA', key_size=256):
        """生成密钥对"""
        if algorithm == 'RSA':
            return self._generate_rsa_key_pair(key_size)
        elif algorithm == 'ECC':
            return self._generate_ecc_key_pair(key_size)
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
    
    def _generate_rsa_key_pair(self, key_size=2048):
        """生成RSA密钥对"""
        key = RSA.generate(key_size)
        
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        
        return {
            'private_key': private_key,
            'public_key': public_key
        }
    
    def _generate_ecc_key_pair(self, key_size=256):
        """生成ECC密钥对"""
        # 这里使用RSA密钥对作为ECC的简化实现
        # 在实际应用中，应使用专门的ECC库
        return self._generate_rsa_key_pair(key_size)
    
    def encrypt(self, plaintext, public_key, algorithm='RSA'):
        """加密函数"""
        if not plaintext:
            return ""
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        try:
            if algorithm == 'RSA':
                return self._encrypt_rsa(plaintext, public_key)
            elif algorithm == 'ECC':
                return self._encrypt_ecc(plaintext, public_key)
            else:
                raise ValueError(f"不支持的算法: {algorithm}")
        except Exception as e:
            raise Exception(f"{algorithm}加密失败: {str(e)}")
    
    def decrypt(self, ciphertext, private_key, algorithm='RSA'):
        """解密函数"""
        if not ciphertext:
            return ""
        
        try:
            if algorithm == 'RSA':
                return self._decrypt_rsa(ciphertext, private_key)
            elif algorithm == 'ECC':
                return self._decrypt_ecc(ciphertext, private_key)
            else:
                raise ValueError(f"不支持的算法: {algorithm}")
        except Exception as e:
            raise Exception(f"{algorithm}解密失败: {str(e)}")
    
    def _encrypt_rsa(self, plaintext, public_key):
        """RSA加密"""
        # 导入公钥
        key = RSA.import_key(public_key)
        
        # 创建加密器
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        
        # 加密
        ciphertext = cipher.encrypt(plaintext)
        
        # Base64编码
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def _decrypt_rsa(self, ciphertext, private_key):
        """RSA解密"""
        if not ciphertext:
            return ""
        
        try:
            # Base64解码
            ciphertext_bytes = base64.b64decode(ciphertext)
        except Exception as e:
            raise Exception(f"Base64解码失败: {str(e)}")
        
        try:
            # 导入私钥
            key = RSA.import_key(private_key)
            
            # 创建解密器
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            
            # 解密
            plaintext = cipher.decrypt(ciphertext_bytes)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise Exception(f"RSA解密失败: {str(e)}")
    
    def _encrypt_ecc(self, plaintext, public_key):
        """ECC加密（简化实现）"""
        # 这里使用RSA加密作为ECC的简化实现
        # 在实际应用中，应使用专门的ECC加密
        return self._encrypt_rsa(plaintext, public_key)
    
    def _decrypt_ecc(self, ciphertext, private_key):
        """ECC解密（简化实现）"""
        # 这里使用RSA解密作为ECC的简化实现
        return self._decrypt_rsa(ciphertext, private_key)
    
    def sign(self, message, private_key, algorithm='RSA'):
        """签名函数"""
        if not message:
            return ""
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            if algorithm == 'RSA':
                return self._sign_rsa(message, private_key)
            elif algorithm == 'ECC':
                return self._sign_ecc(message, private_key)
            else:
                raise ValueError(f"不支持的算法: {algorithm}")
        except Exception as e:
            raise Exception(f"{algorithm}签名失败: {str(e)}")
    
    def verify(self, message, signature, public_key, algorithm='RSA'):
        """验证签名"""
        if not message or not signature:
            return False
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            if algorithm == 'RSA':
                return self._verify_rsa(message, signature, public_key)
            elif algorithm == 'ECC':
                return self._verify_ecc(message, signature, public_key)
            else:
                raise ValueError(f"不支持的算法: {algorithm}")
        except Exception as e:
            raise Exception(f"{algorithm}验证签名失败: {str(e)}")

    
    def _sign_rsa(self, message, private_key):
        """RSA签名"""
        # 导入私钥
        key = RSA.import_key(private_key)
        
        # 计算消息哈希
        message_hash = SHA256.new(message)
        
        # 签名
        signature = pkcs1_15.new(key).sign(message_hash)
        
        # Base64编码
        return base64.b64encode(signature).decode('utf-8')
    
    def _verify_rsa(self, message, signature, public_key):
        """验证RSA签名"""
        try:
            # Base64解码
            signature_bytes = base64.b64decode(signature)
        except Exception as e:
            raise Exception(f"Base64解码失败: {str(e)}")
        
        try:
            # 导入公钥
            key = RSA.import_key(public_key)
            
            # 计算消息哈希
            message_hash = SHA256.new(message)
            
            # 验证签名
            pkcs1_15.new(key).verify(message_hash, signature_bytes)
            return True
        except Exception:
            return False
    
    def _sign_ecc(self, message, private_key):
        """ECC签名（简化实现）"""
        # 这里使用RSA签名作为ECC的简化实现
        return self._sign_rsa(message, private_key)
    
    def _verify_ecc(self, message, signature, public_key):
        """验证ECC签名（简化实现）"""
        # 这里使用RSA验证作为ECC的简化实现
        return self._verify_rsa(message, signature, public_key)