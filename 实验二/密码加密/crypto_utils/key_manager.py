import os
import json
import base64
from datetime import datetime
from .symmetric import SymmetricCrypto
from .asymmetric import AsymmetricCrypto

class KeyManager:
    """密钥管理类"""
    
    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        self.key_info_file = os.path.join(keys_dir, "key_info.json")
        self.symmetric_crypto = SymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()
        
        # 创建密钥目录
        os.makedirs(keys_dir, exist_ok=True)
        
        # 创建密钥信息文件（如果不存在）
        if not os.path.exists(self.key_info_file):
            self._save_key_info({})
    
    def _save_key_info(self, key_info):
        """保存密钥信息"""
        with open(self.key_info_file, 'w', encoding='utf-8') as f:
            json.dump(key_info, f, indent=2, ensure_ascii=False)
    
    def _load_key_info(self):
        """加载密钥信息"""
        try:
            with open(self.key_info_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def generate_symmetric_key(self, key_name, algorithm='SM4'):
        """生成对称密钥"""
        # 检查密钥名称是否已存在
        key_info = self._load_key_info()
        if key_name in key_info:
            raise ValueError(f"密钥名称 '{key_name}' 已存在")
        
        # 生成密钥
        key = self.symmetric_crypto.generate_key(algorithm)
        
        # 保存密钥
        key_file = os.path.join(self.keys_dir, f"{key_name}.key")
        with open(key_file, 'wb') as f:
            f.write(key)
        
        # 保存密钥信息
        key_info[key_name] = {
            'type': 'symmetric',
            'algorithm': algorithm,
            'created_at': datetime.now().isoformat(),
            'file': f"{key_name}.key"
        }
        self._save_key_info(key_info)
        
        return key_name
    
    
    def get_key_list(self):
        """获取密钥列表"""
        key_info = self._load_key_info()
        key_list = []
        
        for key_name, info in key_info.items():
            key_list.append({
                'name': key_name,
                'type': info['type'],
                'algorithm': info['algorithm'],
                'created_at': info['created_at']
            })
        
        return key_list
    
    def get_key_info(self, key_name):
        """获取密钥信息"""
        key_info = self._load_key_info()
        return key_info.get(key_name)
    
    def get_symmetric_key(self, key_name):
        """获取对称密钥"""
        key_info = self._load_key_info()
        
        if key_name not in key_info:
            raise ValueError(f"密钥 '{key_name}' 不存在")
        
        info = key_info[key_name]
        if info['type'] != 'symmetric':
            raise ValueError(f"密钥 '{key_name}' 不是对称密钥")
        
        key_file = os.path.join(self.keys_dir, info['file'])
        if not os.path.exists(key_file):
            raise ValueError(f"密钥文件 '{info['file']}' 不存在")
        
        with open(key_file, 'rb') as f:
            return f.read()
    
    def get_private_key(self, key_name):
        """获取私钥"""
        key_info = self._load_key_info()
        
        if key_name not in key_info:
            raise ValueError(f"密钥 '{key_name}' 不存在")
        
        info = key_info[key_name]
        if info['type'] != 'asymmetric':
            raise ValueError(f"密钥 '{key_name}' 不是非对称密钥")
        
        private_key_file = os.path.join(self.keys_dir, info['private_key_file'])
        if not os.path.exists(private_key_file):
            raise ValueError(f"私钥文件 '{info['private_key_file']}' 不存在")
        
        with open(private_key_file, 'r', encoding='utf-8') as f:
            return f.read()
    
    def get_public_key(self, key_name):
        """获取公钥"""
        key_info = self._load_key_info()
        
        if key_name not in key_info:
            raise ValueError(f"密钥 '{key_name}' 不存在")
        
        info = key_info[key_name]
        if info['type'] != 'asymmetric':
            raise ValueError(f"密钥 '{key_name}' 不是非对称密钥")
        
        public_key_file = os.path.join(self.keys_dir, info['public_key_file'])
        if not os.path.exists(public_key_file):
            raise ValueError(f"公钥文件 '{info['public_key_file']}' 不存在")
        
        with open(public_key_file, 'r', encoding='utf-8') as f:
            return f.read()
    
    def delete_key(self, key_name):
        """删除密钥"""
        key_info = self._load_key_info()
        
        if key_name not in key_info:
            raise ValueError(f"密钥 '{key_name}' 不存在")
        
        info = key_info[key_name]
        
        # 删除密钥文件
        if info['type'] == 'symmetric':
            key_file = os.path.join(self.keys_dir, info['file'])
            if os.path.exists(key_file):
                os.remove(key_file)
        else:
            private_key_file = os.path.join(self.keys_dir, info['private_key_file'])
            public_key_file = os.path.join(self.keys_dir, info['public_key_file'])
            
            if os.path.exists(private_key_file):
                os.remove(private_key_file)
            if os.path.exists(public_key_file):
                os.remove(public_key_file)
        
        # 从密钥信息中删除
        del key_info[key_name]
        self._save_key_info(key_info)
    
    def export_key(self, key_name, export_path):
        """导出密钥"""
        key_info = self._load_key_info()
        
        if key_name not in key_info:
            raise ValueError(f"密钥 '{key_name}' 不存在")
        
        info = key_info[key_name]
        
        if info['type'] == 'symmetric':
            # 导出对称密钥
            key_data = self.get_symmetric_key(key_name)
            
            # Base64编码
            key_base64 = base64.b64encode(key_data).decode('utf-8')
            
            # 创建导出数据
            export_data = {
                'type': 'symmetric',
                'algorithm': info['algorithm'],
                'key': key_base64,
                'created_at': info['created_at']
            }
            
            # 保存到文件
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        else:
            # 导出一对密钥
            private_key = self.get_private_key(key_name)
            public_key = self.get_public_key(key_name)
            
            # 创建导出数据
            export_data = {
                'type': 'asymmetric',
                'algorithm': info['algorithm'],
                'key_size': info['key_size'],
                'private_key': private_key,
                'public_key': public_key,
                'created_at': info['created_at']
            }
            
            # 保存到文件
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def import_key(self, key_name, import_path):
        """导入密钥"""
        # 检查密钥名称是否已存在
        key_info = self._load_key_info()
        if key_name in key_info:
            raise ValueError(f"密钥名称 '{key_name}' 已存在")
        
        # 读取导入文件
        with open(import_path, 'r', encoding='utf-8') as f:
            import_data = json.load(f)
        
        if import_data['type'] == 'symmetric':
            # 导入对称密钥
            key_base64 = import_data['key']
            key_data = base64.b64decode(key_base64.encode('utf-8'))
            
            # 保存密钥
            key_file = os.path.join(self.keys_dir, f"{key_name}.key")
            with open(key_file, 'wb') as f:
                f.write(key_data)
            
            # 保存密钥信息
            key_info[key_name] = {
                'type': 'symmetric',
                'algorithm': import_data['algorithm'],
                'created_at': import_data['created_at'],
                'file': f"{key_name}.key"
            }
        
        else:
            # 导入非对称密钥
            private_key = import_data['private_key']
            public_key = import_data['public_key']
            
            # 保存私钥
            private_key_file = os.path.join(self.keys_dir, f"{key_name}.pri")
            with open(private_key_file, 'w', encoding='utf-8') as f:
                f.write(private_key)
            
            # 保存公钥
            public_key_file = os.path.join(self.keys_dir, f"{key_name}.pub")
            with open(public_key_file, 'w', encoding='utf-8') as f:
                f.write(public_key)
            
            # 保存密钥信息
            key_info[key_name] = {
                'type': 'asymmetric',
                'algorithm': import_data['algorithm'],
                'key_size': import_data['key_size'],
                'created_at': import_data['created_at'],
                'private_key_file': f"{key_name}.pri",
                'public_key_file': f"{key_name}.pub"
            }
        
        self._save_key_info(key_info)
        return key_name