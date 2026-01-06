import os
import base64
import json
from .symmetric import SymmetricCrypto
from .asymmetric import AsymmetricCrypto

class FileCrypto:
    """文件加密类"""
    
    def __init__(self):
        self.symmetric_crypto = SymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.chunk_size = 64 * 1024  # 64KB 分块大小
    
    def encrypt_file(self, input_file, output_file, key, algorithm='SM4', encryption_type='symmetric'):
        """加密文件"""
        try:
            if encryption_type == 'symmetric':
                return self._encrypt_file_symmetric(input_file, output_file, key, algorithm)
            elif encryption_type == 'asymmetric':
                return self._encrypt_file_asymmetric(input_file, output_file, key, algorithm)
            else:
                raise ValueError(f"不支持的加密类型: {encryption_type}")
        except Exception as e:
            raise Exception(f"文件加密失败: {str(e)}")
    
    def decrypt_file(self, input_file, output_file, key, algorithm='SM4', encryption_type='symmetric'):
        """解密文件"""
        try:
            if encryption_type == 'symmetric':
                return self._decrypt_file_symmetric(input_file, output_file, key, algorithm)
            elif encryption_type == 'asymmetric':
                return self._decrypt_file_asymmetric(input_file, output_file, key, algorithm)
            else:
                raise ValueError(f"不支持的加密类型: {encryption_type}")
        except Exception as e:
            raise Exception(f"文件解密失败: {str(e)}")
    
    def _encrypt_file_symmetric(self, input_file, output_file, key, algorithm):
        """对称加密文件"""
        # 读取输入文件信息
        file_size = os.path.getsize(input_file)
        file_name = os.path.basename(input_file)
        
        # 创建加密头信息
        header = {
            'algorithm': algorithm,
            'encryption_type': 'symmetric',
            'file_name': file_name,
            'file_size': file_size
        }
        
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            # 写入文件头
            header_json = json.dumps(header, ensure_ascii=False)
            header_bytes = header_json.encode('utf-8')
            header_length = len(header_bytes)
            
            # 写入头部长度（4字节）
            outfile.write(header_length.to_bytes(4, byteorder='big'))
            # 写入头部数据
            outfile.write(header_bytes)
            
            # 分块加密
            while True:
                chunk = infile.read(self.chunk_size)
                if not chunk:
                    break
                
                # 将二进制数据转换为base64字符串进行加密
                chunk_base64 = base64.b64encode(chunk).decode('utf-8')
                encrypted_chunk = self.symmetric_crypto.encrypt(chunk_base64, key, algorithm)
                
                # 写入加密数据长度（4字节）
                encrypted_bytes = encrypted_chunk.encode('utf-8')
                chunk_length = len(encrypted_bytes)
                outfile.write(chunk_length.to_bytes(4, byteorder='big'))
                # 写入加密数据
                outfile.write(encrypted_bytes)
        
        return True
    
    def _decrypt_file_symmetric(self, input_file, output_file, key, algorithm):
        """对称解密文件"""
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            # 读取头部长度
            header_length_bytes = infile.read(4)
            if len(header_length_bytes) != 4:
                raise Exception("无效的文件格式")
            
            header_length = int.from_bytes(header_length_bytes, byteorder='big')
            
            # 读取头部数据
            header_bytes = infile.read(header_length)
            header_json = header_bytes.decode('utf-8')
            header = json.loads(header_json)
            
            # 验证算法
            if header['algorithm'] != algorithm:
                raise Exception(f"算法不匹配: 文件使用 {header['algorithm']}, 但尝试使用 {algorithm} 解密")
            
            # 分块解密
            while True:
                # 读取块长度
                chunk_length_bytes = infile.read(4)
                if not chunk_length_bytes:
                    break
                
                if len(chunk_length_bytes) != 4:
                    raise Exception("无效的文件格式")
                
                chunk_length = int.from_bytes(chunk_length_bytes, byteorder='big')
                
                # 读取加密数据
                encrypted_bytes = infile.read(chunk_length)
                if len(encrypted_bytes) != chunk_length:
                    raise Exception("文件损坏")
                
                # 解密
                encrypted_chunk = encrypted_bytes.decode('utf-8')
                decrypted_chunk = self.symmetric_crypto.decrypt(encrypted_chunk, key, algorithm)
                
                # 将base64字符串转换回二进制数据
                chunk = base64.b64decode(decrypted_chunk.encode('utf-8'))
                
                # 写入解密数据
                outfile.write(chunk)
        
        return True
    
    def _encrypt_file_asymmetric(self, input_file, output_file, public_key, algorithm):
        """非对称加密文件"""
        # 由于非对称加密不适合加密大文件，我们采用混合加密方案
        # 1. 生成一个随机的对称密钥
        # 2. 使用对称密钥加密文件内容
        # 3. 使用非对称密钥加密对称密钥
        
        # 生成随机的对称密钥
        session_key = self.symmetric_crypto.generate_key('SM4')
        
        # 读取输入文件信息
        file_size = os.path.getsize(input_file)
        file_name = os.path.basename(input_file)
        
        # 创建加密头信息
        header = {
            'algorithm': algorithm,
            'encryption_type': 'asymmetric',
            'file_name': file_name,
            'file_size': file_size,
            'session_algorithm': 'SM4'
        }
        
        # 加密会话密钥
        encrypted_session_key = self.asymmetric_crypto.encrypt(
            base64.b64encode(session_key).decode('utf-8'), 
            public_key, 
            algorithm
        )
        
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            # 写入文件头
            header_json = json.dumps(header, ensure_ascii=False)
            header_bytes = header_json.encode('utf-8')
            header_length = len(header_bytes)
            
            # 写入头部长度（4字节）
            outfile.write(header_length.to_bytes(4, byteorder='big'))
            # 写入头部数据
            outfile.write(header_bytes)
            
            # 写入加密的会话密钥长度（4字节）
            encrypted_session_key_bytes = encrypted_session_key.encode('utf-8')
            session_key_length = len(encrypted_session_key_bytes)
            outfile.write(session_key_length.to_bytes(4, byteorder='big'))
            # 写入加密的会话密钥
            outfile.write(encrypted_session_key_bytes)
            
            # 使用会话密钥分块加密文件内容
            while True:
                chunk = infile.read(self.chunk_size)
                if not chunk:
                    break
                
                # 将二进制数据转换为base64字符串进行加密
                chunk_base64 = base64.b64encode(chunk).decode('utf-8')
                encrypted_chunk = self.symmetric_crypto.encrypt(chunk_base64, session_key, 'SM4')
                
                # 写入加密数据长度（4字节）
                encrypted_bytes = encrypted_chunk.encode('utf-8')
                chunk_length = len(encrypted_bytes)
                outfile.write(chunk_length.to_bytes(4, byteorder='big'))
                # 写入加密数据
                outfile.write(encrypted_bytes)
        
        return True
    
    def _decrypt_file_asymmetric(self, input_file, output_file, private_key, algorithm):
        """非对称解密文件"""
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            # 读取头部长度
            header_length_bytes = infile.read(4)
            if len(header_length_bytes) != 4:
                raise Exception("无效的文件格式")
            
            header_length = int.from_bytes(header_length_bytes, byteorder='big')
            
            # 读取头部数据
            header_bytes = infile.read(header_length)
            header_json = header_bytes.decode('utf-8')
            header = json.loads(header_json)
            
            # 验证算法
            if header['algorithm'] != algorithm:
                raise Exception(f"算法不匹配: 文件使用 {header['algorithm']}, 但尝试使用 {algorithm} 解密")
            
            # 读取加密的会话密钥长度
            session_key_length_bytes = infile.read(4)
            if len(session_key_length_bytes) != 4:
                raise Exception("无效的文件格式")
            
            session_key_length = int.from_bytes(session_key_length_bytes, byteorder='big')
            
            # 读取加密的会话密钥
            encrypted_session_key_bytes = infile.read(session_key_length)
            if len(encrypted_session_key_bytes) != session_key_length:
                raise Exception("文件损坏")
            
            # 解密会话密钥
            encrypted_session_key = encrypted_session_key_bytes.decode('utf-8')
            session_key_base64 = self.asymmetric_crypto.decrypt(
                encrypted_session_key, private_key, algorithm
            )
            session_key = base64.b64decode(session_key_base64.encode('utf-8'))
            
            # 使用会话密钥分块解密文件内容
            while True:
                # 读取块长度
                chunk_length_bytes = infile.read(4)
                if not chunk_length_bytes:
                    break
                
                if len(chunk_length_bytes) != 4:
                    raise Exception("无效的文件格式")
                
                chunk_length = int.from_bytes(chunk_length_bytes, byteorder='big')
                
                # 读取加密数据
                encrypted_bytes = infile.read(chunk_length)
                if len(encrypted_bytes) != chunk_length:
                    raise Exception("文件损坏")
                
                # 解密
                encrypted_chunk = encrypted_bytes.decode('utf-8')
                decrypted_chunk = self.symmetric_crypto.decrypt(encrypted_chunk, session_key, 'SM4')
                
                # 将base64字符串转换回二进制数据
                chunk = base64.b64decode(decrypted_chunk.encode('utf-8'))
                
                # 写入解密数据
                outfile.write(chunk)
        
        return True
    
    def get_file_info(self, encrypted_file):
        """获取加密文件信息"""
        try:
            with open(encrypted_file, 'rb') as f:
                # 读取头部长度
                header_length_bytes = f.read(4)
                if len(header_length_bytes) != 4:
                    return None
                
                header_length = int.from_bytes(header_length_bytes, byteorder='big')
                
                # 读取头部数据
                header_bytes = f.read(header_length)
                header_json = header_bytes.decode('utf-8')
                header = json.loads(header_json)
                
                return header
        except Exception:
            return None