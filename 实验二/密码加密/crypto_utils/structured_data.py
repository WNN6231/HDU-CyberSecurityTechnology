import pandas as pd
import numpy as np
import json
import base64
from .symmetric import SymmetricCrypto

class StructuredDataCrypto:
    """结构化数据加密类"""
    
    def __init__(self):
        self.symmetric_crypto = SymmetricCrypto()
        self.supported_extensions = ['.csv', '.xlsx', '.xls']
    
    def encrypt_data(self, input_file, output_file, key, algorithm='SM4', mode='full', columns=None, fields=None):
        """加密结构化数据"""
        try:
            # 读取数据
            df = self._read_data(input_file)
            if df is None:
                raise Exception("无法读取数据文件")
            
            # 根据模式加密数据
            if mode == 'full':
                encrypted_df = self._encrypt_full_table(df, key, algorithm)
            elif mode == 'column':
                if not columns:
                    raise ValueError("列加密模式需要指定列名")
                encrypted_df = self._encrypt_columns(df, key, algorithm, columns)
            elif mode == 'field':
                if not fields:
                    raise ValueError("字段加密模式需要指定字段")
                encrypted_df = self._encrypt_fields(df, key, algorithm, fields)
            else:
                raise ValueError(f"不支持的加密模式: {mode}")
            
            # 保存加密数据
            self._save_data(encrypted_df, output_file)
            
            return True
        except Exception as e:
            raise Exception(f"数据加密失败: {str(e)}")
    
    def decrypt_data(self, input_file, output_file, key, algorithm='SM4', mode='full', columns=None, fields=None):
        """解密结构化数据"""
        try:
            # 读取加密数据
            df = self._read_data(input_file)
            if df is None:
                raise Exception("无法读取加密数据文件")
            
            # 根据模式解密数据
            if mode == 'full':
                decrypted_df = self._decrypt_full_table(df, key, algorithm)
            elif mode == 'column':
                if not columns:
                    raise ValueError("列解密模式需要指定列名")
                decrypted_df = self._decrypt_columns(df, key, algorithm, columns)
            elif mode == 'field':
                if not fields:
                    raise ValueError("字段解密模式需要指定字段")
                decrypted_df = self._decrypt_fields(df, key, algorithm, fields)
            else:
                raise ValueError(f"不支持的解密模式: {mode}")
            
            # 保存解密数据
            self._save_data(decrypted_df, output_file)
            
            return True
        except Exception as e:
            raise Exception(f"数据解密失败: {str(e)}")
    
    def _read_data(self, file_path):
        """读取数据文件"""
        try:
            if file_path.endswith('.csv'):
                return pd.read_csv(file_path)
            elif file_path.endswith('.xlsx') or file_path.endswith('.xls'):
                return pd.read_excel(file_path)
            else:
                raise ValueError(f"不支持的文件格式: {file_path}")
        except Exception as e:
            raise Exception(f"读取数据文件失败: {str(e)}")
    
    def _save_data(self, df, file_path):
        """保存数据文件"""
        try:
            if file_path.endswith('.csv'):
                df.to_csv(file_path, index=False)
            elif file_path.endswith('.xlsx') or file_path.endswith('.xls'):
                df.to_excel(file_path, index=False)
            else:
                raise ValueError(f"不支持的文件格式: {file_path}")
        except Exception as e:
            raise Exception(f"保存数据文件失败: {str(e)}")
    
    def _encrypt_full_table(self, df, key, algorithm):
        """全表加密"""
        # 将DataFrame转换为JSON字符串
        json_str = df.to_json(orient='records', force_ascii=False)
        
        # 加密JSON字符串
        encrypted_json = self.symmetric_crypto.encrypt(json_str, key, algorithm)
        
        # 创建加密后的DataFrame
        encrypted_df = pd.DataFrame({
            'encrypted_data': [encrypted_json]
        })
        
        return encrypted_df
    
    def _decrypt_full_table(self, df, key, algorithm):
        """全表解密"""
        # 检查数据结构
        if len(df) != 1 or 'encrypted_data' not in df.columns:
            raise Exception("无效的加密数据格式")
        
        # 获取加密数据
        encrypted_json = df['encrypted_data'].iloc[0]
        
        # 解密JSON字符串
        json_str = self.symmetric_crypto.decrypt(encrypted_json, key, algorithm)
        print('解密后JSON字符串:', json_str)
        # 将JSON字符串转换回DataFrame
        data = json.loads(json_str)
        print('解密后Data:', data)
        decrypted_df = pd.DataFrame(data)
        print('解密后DataFrame:', decrypted_df)
        
        return decrypted_df
    
    def _encrypt_columns(self, df, key, algorithm, columns):
        """列加密"""
        encrypted_df = df.copy()
        
        for column in columns:
            if column not in df.columns:
                raise ValueError(f"列 '{column}' 不存在")
            
            # 将列数据转换为字符串
            column_data = df[column].astype(str).tolist()
            
            # 将列数据转换为JSON字符串
            json_str = json.dumps(column_data, ensure_ascii=False)
            
            # 加密JSON字符串
            encrypted_json = self.symmetric_crypto.encrypt(json_str, key, algorithm)
            
            # 替换列数据为加密数据
            encrypted_df[column] = encrypted_json
        
        # 添加加密标记
        encrypted_df['_encrypted_columns'] = ','.join(columns)
        
        return encrypted_df
    
    def _decrypt_columns(self, df, key, algorithm, columns):
        """列解密"""
        # 检查加密标记
        if '_encrypted_columns' not in df.columns:
            raise Exception("未找到加密列信息")
        
        encrypted_columns_str = df['_encrypted_columns'].iloc[0]
        encrypted_columns = encrypted_columns_str.split(',')
        
        decrypted_df = df.copy()
        
        for column in columns:
            if column not in encrypted_columns:
                raise ValueError(f"列 '{column}' 未加密")
            
            if column not in df.columns:
                raise ValueError(f"列 '{column}' 不存在")
            
            # 获取加密数据
            encrypted_json = df[column].iloc[0]
            
            # 解密JSON字符串
            json_str = self.symmetric_crypto.decrypt(encrypted_json, key, algorithm)
            
            # 将JSON字符串转换回列表
            column_data = json.loads(json_str)
            
            # 替换列数据
            decrypted_df = decrypted_df.copy()
            decrypted_df[column] = column_data
        
        # 移除加密标记
        decrypted_df = decrypted_df.drop(columns=['_encrypted_columns'])
        
        return decrypted_df
    
    def _encrypt_fields(self, df, key, algorithm, fields):
        """字段加密"""
        encrypted_df = df.copy()
        
        for field in fields:
            # 解析字段格式 (行索引,列名)
            if ',' not in field:
                raise ValueError(f"字段格式错误: {field}")
            
            row_str, column = field.split(',', 1)
            try:
                row = int(row_str)
            except ValueError:
                raise ValueError(f"行索引必须是数字: {row_str}")
            
            if column not in df.columns:
                raise ValueError(f"列 '{column}' 不存在")
            
            if row >= len(df):
                raise ValueError(f"行索引超出范围: {row}")
            
            # 获取字段值
            field_value = str(df[column].iloc[row])
            
            # 加密字段值
            encrypted_value = self.symmetric_crypto.encrypt(field_value, key, algorithm)
            
            # 替换字段值
            encrypted_df.loc[row, column] = encrypted_value
        
        # 添加加密标记
        encrypted_df['_encrypted_fields'] = ','.join(fields)
        
        return encrypted_df
    
    def _decrypt_fields(self, df, key, algorithm, fields):
        """字段解密"""
        # 检查加密标记
        if '_encrypted_fields' not in df.columns:
            raise Exception("未找到加密字段信息")
        
        encrypted_fields_str = df['_encrypted_fields'].iloc[0]
        encrypted_fields = encrypted_fields_str.split(',')
        
        decrypted_df = df.copy()
        
        for field in fields:
            if field not in encrypted_fields:
                raise ValueError(f"字段 '{field}' 未加密")
            
            # 解析字段格式 (行索引,列名)
            row_str, column = field.split(',', 1)
            try:
                row = int(row_str)
            except ValueError:
                raise ValueError(f"行索引必须是数字: {row_str}")
            
            if column not in df.columns:
                raise ValueError(f"列 '{column}' 不存在")
            
            if row >= len(df):
                raise ValueError(f"行索引超出范围: {row}")
            
            # 获取加密值
            encrypted_value = df[column].iloc[row]
            
            # 解密字段值
            decrypted_value = self.symmetric_crypto.decrypt(encrypted_value, key, algorithm)
            
            # 替换字段值
            decrypted_df.loc[row, column] = decrypted_value
        
        # 移除加密标记
        decrypted_df = decrypted_df.drop(columns=['_encrypted_fields'])
        
        return decrypted_df
    
    def get_data_preview(self, file_path, max_rows=10):
        """获取数据预览"""
        try:
            df = self._read_data(file_path)
            if df is None:
                return None
            
            # 返回前max_rows行
            preview_df = df.head(max_rows)
            
            # 转换为字典格式
            preview_data = {
                'columns': preview_df.columns.tolist(),
                'data': preview_df.values.tolist(),
                'shape': df.shape
            }
            
            return preview_data
        except Exception as e:
            raise Exception(f"获取数据预览失败: {str(e)}")
    
    def get_column_list(self, file_path):
        """获取列列表"""
        try:
            df = self._read_data(file_path)
            if df is None:
                return []
            
            return df.columns.tolist()
        except Exception as e:
            raise Exception(f"获取列列表失败: {str(e)}")
    
    def is_supported_format(self, file_path):
        """检查是否支持文件格式"""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.supported_extensions