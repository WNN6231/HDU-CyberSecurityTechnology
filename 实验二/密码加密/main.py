import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, 
                             QComboBox, QRadioButton, QButtonGroup, QTableWidget, 
                             QTableWidgetItem, QFileDialog, QMessageBox, QProgressBar,
                             QGroupBox, QSplitter, QListWidget, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

from crypto_utils.key_manager import KeyManager
from crypto_utils.symmetric import SymmetricCrypto
from crypto_utils.asymmetric import AsymmetricCrypto
from crypto_utils.file_crypto import FileCrypto
from crypto_utils.structured_data import StructuredDataCrypto

class EncryptionThread(QThread):
    """加密线程"""
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, crypto_obj, method, *args, **kwargs):
        super().__init__()
        self.crypto_obj = crypto_obj
        self.method = method
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            result = self.method(*self.args, **self.kwargs)
            self.finished.emit(True, "操作成功")
        except Exception as e:
            self.finished.emit(False, str(e))

class MainWindow(QMainWindow):
    """主窗口"""
    
    def __init__(self):
        super().__init__()
        self.key_manager = KeyManager()
        self.symmetric_crypto = SymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.file_crypto = FileCrypto()
        self.structured_crypto = StructuredDataCrypto()
        
        self.init_ui()
        self.update_key_lists()
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle('综合加密系统')
        self.setGeometry(100, 100, 1200, 800)
        
        # 创建中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标题
        title_label = QLabel('综合加密系统')
        title_label.setFont(QFont('Arial', 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # 创建各个标签页
        self.create_text_tab()
        self.create_file_tab()
        self.create_structured_data_tab()
        self.create_key_management_tab()
    
    def create_text_tab(self):
        """创建文本加密标签页"""
        text_tab = QWidget()
        self.tab_widget.addTab(text_tab, "文本加密")
        
        layout = QVBoxLayout(text_tab)
        
        # 加密类型选择
        type_group = QGroupBox("加密类型")
        type_layout = QHBoxLayout()
        
        self.text_type_group = QButtonGroup()
        self.text_symmetric_radio = QRadioButton("对称加密")
        self.text_asymmetric_radio = QRadioButton("非对称加密")
        self.text_symmetric_radio.setChecked(True)
        
        self.text_type_group.addButton(self.text_symmetric_radio)
        self.text_type_group.addButton(self.text_asymmetric_radio)
        
        type_layout.addWidget(self.text_symmetric_radio)
        type_layout.addWidget(self.text_asymmetric_radio)
        type_group.setLayout(type_layout)
        layout.addWidget(type_group)
        
        # 算法和密钥选择
        algo_group = QGroupBox("算法和密钥")
        algo_layout = QHBoxLayout()
        
        algo_layout.addWidget(QLabel("算法:"))
        self.text_algorithm_combo = QComboBox()
        algo_layout.addWidget(self.text_algorithm_combo)
        
        algo_layout.addWidget(QLabel("密钥:"))
        self.text_key_combo = QComboBox()
        algo_layout.addWidget(self.text_key_combo)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # 输入输出区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        input_layout.addWidget(self.text_input)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        self.text_encrypt_btn = QPushButton("加密")
        self.text_decrypt_btn = QPushButton("解密")
        self.text_clear_btn = QPushButton("清空")
        
        self.text_encrypt_btn.clicked.connect(self.encrypt_text)
        self.text_decrypt_btn.clicked.connect(self.decrypt_text)
        self.text_clear_btn.clicked.connect(self.clear_text)
        
        button_layout.addWidget(self.text_encrypt_btn)
        button_layout.addWidget(self.text_decrypt_btn)
        button_layout.addWidget(self.text_clear_btn)
        layout.addLayout(button_layout)
        
        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.text_output = QTextEdit()
        # 输出框不设置为只读，允许用户输入密文进行解密
        output_layout.addWidget(self.text_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # 连接信号
        self.text_symmetric_radio.toggled.connect(self.update_text_algorithm_list)
        self.text_asymmetric_radio.toggled.connect(self.update_text_algorithm_list)
        
        # 初始化算法列表
        self.update_text_algorithm_list()
    
    def create_file_tab(self):
        """创建文件加密标签页"""
        file_tab = QWidget()
        self.tab_widget.addTab(file_tab, "文件加密")
        
        layout = QVBoxLayout(file_tab)
        
        # 文件选择
        file_group = QGroupBox("文件选择")
        file_layout = QHBoxLayout()
        
        file_layout.addWidget(QLabel("文件路径:"))
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        file_layout.addWidget(self.file_path_edit)
        
        self.file_browse_btn = QPushButton("浏览")
        self.file_browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_browse_btn)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # 加密类型选择
        type_group = QGroupBox("加密类型")
        type_layout = QHBoxLayout()
        
        self.file_type_group = QButtonGroup()
        self.file_symmetric_radio = QRadioButton("对称加密")
        self.file_asymmetric_radio = QRadioButton("非对称加密")
        self.file_symmetric_radio.setChecked(True)
        
        self.file_type_group.addButton(self.file_symmetric_radio)
        self.file_type_group.addButton(self.file_asymmetric_radio)
        
        type_layout.addWidget(self.file_symmetric_radio)
        type_layout.addWidget(self.file_asymmetric_radio)
        type_group.setLayout(type_layout)
        layout.addWidget(type_group)
        
        # 算法和密钥选择
        algo_group = QGroupBox("算法和密钥")
        algo_layout = QHBoxLayout()
        
        algo_layout.addWidget(QLabel("算法:"))
        self.file_algorithm_combo = QComboBox()
        algo_layout.addWidget(self.file_algorithm_combo)
        
        algo_layout.addWidget(QLabel("密钥:"))
        self.file_key_combo = QComboBox()
        algo_layout.addWidget(self.file_key_combo)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # 进度条
        self.file_progress = QProgressBar()
        layout.addWidget(self.file_progress)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        self.file_encrypt_btn = QPushButton("加密文件")
        self.file_decrypt_btn = QPushButton("解密文件")
        
        self.file_encrypt_btn.clicked.connect(self.encrypt_file)
        self.file_decrypt_btn.clicked.connect(self.decrypt_file)
        
        button_layout.addWidget(self.file_encrypt_btn)
        button_layout.addWidget(self.file_decrypt_btn)
        layout.addLayout(button_layout)
        
        # 连接信号
        self.file_symmetric_radio.toggled.connect(self.update_file_algorithm_list)
        self.file_asymmetric_radio.toggled.connect(self.update_file_algorithm_list)
        
        # 初始化算法列表
        self.update_file_algorithm_list()
    
    def create_structured_data_tab(self):
        """创建结构化数据加密标签页"""
        data_tab = QWidget()
        self.tab_widget.addTab(data_tab, "结构化数据加密")
        
        layout = QVBoxLayout(data_tab)
        
        # 文件选择
        file_group = QGroupBox("文件选择")
        file_layout = QHBoxLayout()
        
        file_layout.addWidget(QLabel("数据文件:"))
        self.data_path_edit = QLineEdit()
        self.data_path_edit.setReadOnly(True)
        file_layout.addWidget(self.data_path_edit)
        
        self.data_browse_btn = QPushButton("浏览")
        self.data_browse_btn.clicked.connect(self.browse_data_file)
        file_layout.addWidget(self.data_browse_btn)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # 加密模式选择
        mode_group = QGroupBox("加密模式")
        mode_layout = QVBoxLayout()
        
        self.data_full_radio = QRadioButton("全表加密")
        self.data_column_radio = QRadioButton("列加密")
        self.data_field_radio = QRadioButton("字段加密")
        self.data_full_radio.setChecked(True)
        
        mode_layout.addWidget(self.data_full_radio)
        mode_layout.addWidget(self.data_column_radio)
        mode_layout.addWidget(self.data_field_radio)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # 列/字段选择
        select_group = QGroupBox("列/字段选择")
        select_layout = QHBoxLayout()
        
        self.column_list = QListWidget()
        self.column_list.setSelectionMode(QListWidget.MultiSelection)
        select_layout.addWidget(self.column_list)
        
        self.data_preview = QTableWidget()
        self.data_preview.setMaximumHeight(200)
        select_layout.addWidget(self.data_preview)
        
        select_group.setLayout(select_layout)
        layout.addWidget(select_group)
        
        # 算法和密钥选择
        algo_group = QGroupBox("算法和密钥")
        algo_layout = QHBoxLayout()
        
        algo_layout.addWidget(QLabel("算法:"))
        self.data_algorithm_combo = QComboBox()
        algo_layout.addWidget(self.data_algorithm_combo)
        
        algo_layout.addWidget(QLabel("密钥:"))
        self.data_key_combo = QComboBox()
        algo_layout.addWidget(self.data_key_combo)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # 进度条
        self.data_progress = QProgressBar()
        layout.addWidget(self.data_progress)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        self.data_encrypt_btn = QPushButton("加密数据")
        self.data_decrypt_btn = QPushButton("解密数据")
        
        self.data_encrypt_btn.clicked.connect(self.encrypt_data)
        self.data_decrypt_btn.clicked.connect(self.decrypt_data)
        
        button_layout.addWidget(self.data_encrypt_btn)
        button_layout.addWidget(self.data_decrypt_btn)
        layout.addLayout(button_layout)
        
        # 连接信号
        self.data_column_radio.toggled.connect(self.update_column_selection)
        self.data_field_radio.toggled.connect(self.update_column_selection)
        
        # 初始化算法列表
        self.update_data_algorithm_list()
    
    def create_key_management_tab(self):
        """创建密钥管理标签页"""
        key_tab = QWidget()
        self.tab_widget.addTab(key_tab, "密钥管理")
        
        layout = QVBoxLayout(key_tab)
        
        # 密钥生成区域
        gen_group = QGroupBox("生成新密钥")
        gen_layout = QVBoxLayout()
        
        # 密钥类型选择
        type_layout = QHBoxLayout()
        self.key_type_group = QButtonGroup()
        self.key_symmetric_radio = QRadioButton("对称密钥")
        self.key_asymmetric_radio = QRadioButton("非对称密钥")
        self.key_symmetric_radio.setChecked(True)
        
        self.key_type_group.addButton(self.key_symmetric_radio)
        self.key_type_group.addButton(self.key_asymmetric_radio)
        
        type_layout.addWidget(self.key_symmetric_radio)
        type_layout.addWidget(self.key_asymmetric_radio)
        gen_layout.addLayout(type_layout)
        
        # 密钥信息输入
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("密钥名称:"))
        self.key_name_edit = QLineEdit()
        info_layout.addWidget(self.key_name_edit)
        
        info_layout.addWidget(QLabel("算法:"))
        self.key_algorithm_combo = QComboBox()
        info_layout.addWidget(self.key_algorithm_combo)
        
        info_layout.addWidget(QLabel("密钥长度:"))
        self.key_length_combo = QComboBox()
        info_layout.addWidget(self.key_length_combo)
        
        gen_layout.addLayout(info_layout)
        
        # 生成按钮
        self.key_generate_btn = QPushButton("生成密钥")
        self.key_generate_btn.clicked.connect(self.generate_key)
        gen_layout.addWidget(self.key_generate_btn)
        
        gen_group.setLayout(gen_layout)
        layout.addWidget(gen_group)
        
        # 密钥列表
        list_group = QGroupBox("密钥列表")
        list_layout = QVBoxLayout()
        
        self.key_table = QTableWidget()
        self.key_table.setColumnCount(4)
        self.key_table.setHorizontalHeaderLabels(["密钥名称", "类型", "算法", "创建时间"])
        list_layout.addWidget(self.key_table)
        
        # 密钥操作按钮
        key_op_layout = QHBoxLayout()
        self.key_import_btn = QPushButton("导入密钥")
        self.key_export_btn = QPushButton("导出密钥")
        self.key_delete_btn = QPushButton("删除密钥")
        
        self.key_import_btn.clicked.connect(self.import_key)
        self.key_export_btn.clicked.connect(self.export_key)
        self.key_delete_btn.clicked.connect(self.delete_key)
        
        key_op_layout.addWidget(self.key_import_btn)
        key_op_layout.addWidget(self.key_export_btn)
        key_op_layout.addWidget(self.key_delete_btn)
        list_layout.addLayout(key_op_layout)
        
        list_group.setLayout(list_layout)
        layout.addWidget(list_group)
        
        # 连接信号
        self.key_symmetric_radio.toggled.connect(self.update_key_algorithm_list)
        self.key_asymmetric_radio.toggled.connect(self.update_key_algorithm_list)
        
        # 初始化算法列表
        self.update_key_algorithm_list()
    
    def update_text_algorithm_list(self):
        """更新文本加密算法列表"""
        self.text_algorithm_combo.clear()
        if self.text_symmetric_radio.isChecked():
            self.text_algorithm_combo.addItems(['SM4', 'AES', '3DES'])
        else:
            self.text_algorithm_combo.addItems(['RSA', 'ECC'])
        self.update_text_key_list()
    
    def update_text_key_list(self):
        """更新文本加密密钥列表"""
        self.text_key_combo.clear()
        key_list = self.key_manager.get_key_list()
        
        if self.text_symmetric_radio.isChecked():
            # 对称加密
            for key_info in key_list:
                if key_info['type'] == 'symmetric':
                    self.text_key_combo.addItem(key_info['name'])
        else:
            # 非对称加密
            for key_info in key_list:
                if key_info['type'] == 'asymmetric':
                    self.text_key_combo.addItem(key_info['name'])
    
    def update_file_algorithm_list(self):
        """更新文件加密算法列表"""
        self.file_algorithm_combo.clear()
        if self.file_symmetric_radio.isChecked():
            self.file_algorithm_combo.addItems(['SM4', 'AES', '3DES'])
        else:
            self.file_algorithm_combo.addItems(['RSA', 'ECC'])
        self.update_file_key_list()
    
    def update_file_key_list(self):
        """更新文件加密密钥列表"""
        self.file_key_combo.clear()
        key_list = self.key_manager.get_key_list()
        
        if self.file_symmetric_radio.isChecked():
            # 对称加密
            for key_info in key_list:
                if key_info['type'] == 'symmetric':
                    self.file_key_combo.addItem(key_info['name'])
        else:
            # 非对称加密
            for key_info in key_list:
                if key_info['type'] == 'asymmetric':
                    self.file_key_combo.addItem(key_info['name'])
    
    def update_data_algorithm_list(self):
        """更新数据加密算法列表"""
        self.data_algorithm_combo.clear()
        self.data_algorithm_combo.addItems(['SM4', 'AES', '3DES'])
        self.update_data_key_list()
    
    def update_data_key_list(self):
        """更新数据加密密钥列表"""
        self.data_key_combo.clear()
        key_list = self.key_manager.get_key_list()
        
        # 数据加密只使用对称加密
        for key_info in key_list:
            if key_info['type'] == 'symmetric':
                self.data_key_combo.addItem(key_info['name'])
    
    def update_key_algorithm_list(self):
        """更新密钥管理算法列表"""
        self.key_algorithm_combo.clear()
        self.key_length_combo.clear()
        
        if self.key_symmetric_radio.isChecked():
            # 对称密钥
            self.key_algorithm_combo.addItems(['SM4', 'AES', '3DES'])
            self.key_length_combo.addItems(['固定'])
        else:
            # 非对称密钥
            self.key_algorithm_combo.addItems(['RSA', 'ECC'])
            self.key_length_combo.addItems(['256', '512', '1024', '2048'])
            self.key_length_combo.setCurrentText('256')
    
    def update_key_lists(self):
        """更新所有密钥列表"""
        self.update_text_key_list()
        self.update_file_key_list()
        self.update_data_key_list()
        self.update_key_table()
    
    def update_key_table(self):
        """更新密钥表格"""
        key_list = self.key_manager.get_key_list()
        self.key_table.setRowCount(len(key_list))
        
        for row, key_info in enumerate(key_list):
            self.key_table.setItem(row, 0, QTableWidgetItem(key_info['name']))
            self.key_table.setItem(row, 1, QTableWidgetItem(key_info['type']))
            self.key_table.setItem(row, 2, QTableWidgetItem(key_info['algorithm']))
            self.key_table.setItem(row, 3, QTableWidgetItem(key_info['created_at']))
        
        self.key_table.resizeColumnsToContents()
    
    def browse_file(self):
        """浏览文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)")
        if file_path:
            self.file_path_edit.setText(file_path)
    
    def browse_data_file(self):
        """浏览数据文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择数据文件", "", 
                                                 "Excel文件 (*.xlsx *.xls);;CSV文件 (*.csv)")
        if file_path:
            self.data_path_edit.setText(file_path)
            self.update_data_preview(file_path)
    
    def update_data_preview(self, file_path):
        """更新数据预览"""
        try:
            preview_data = self.structured_crypto.get_data_preview(file_path)
            if preview_data:
                # 更新表格
                self.data_preview.setRowCount(len(preview_data['data']))
                self.data_preview.setColumnCount(len(preview_data['columns']))
                self.data_preview.setHorizontalHeaderLabels(preview_data['columns'])
                
                for row, data_row in enumerate(preview_data['data']):
                    for col, value in enumerate(data_row):
                        self.data_preview.setItem(row, col, QTableWidgetItem(str(value)))
                
                self.data_preview.resizeColumnsToContents()
                
                # 更新列列表
                self.column_list.clear()
                self.column_list.addItems(preview_data['columns'])
        except Exception as e:
            QMessageBox.warning(self, "警告", f"无法预览数据: {str(e)}")
    
    def update_column_selection(self):
        """更新列选择状态"""
        if self.data_column_radio.isChecked() or self.data_field_radio.isChecked():
            self.column_list.setEnabled(True)
        else:
            self.column_list.setEnabled(False)
    
    def encrypt_text(self):
        """加密文本"""
        try:
            plaintext = self.text_input.toPlainText()
            if not plaintext:
                QMessageBox.warning(self, "警告", "请输入要加密的文本")
                return
            
            algorithm = self.text_algorithm_combo.currentText()
            key_name = self.text_key_combo.currentText()
            
            if not key_name:
                QMessageBox.warning(self, "警告", "请选择密钥")
                return
            
            if self.text_symmetric_radio.isChecked():
                # 对称加密
                key = self.key_manager.get_symmetric_key(key_name)
                ciphertext = self.symmetric_crypto.encrypt(plaintext, key, algorithm)
            else:
                # 非对称加密
                public_key = self.key_manager.get_public_key(key_name)
                ciphertext = self.asymmetric_crypto.encrypt(plaintext, public_key, algorithm)
            
            self.text_output.setPlainText(ciphertext)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")
    
    def decrypt_text(self):
        """解密文本"""
        try:
            # 优先从输出框获取密文，如果没有则从输入框获取
            ciphertext = self.text_output.toPlainText()
            if not ciphertext:
                ciphertext = self.text_input.toPlainText()
            
            if not ciphertext:
                QMessageBox.warning(self, "警告", "请输入要解密的密文")
                return
            
            algorithm = self.text_algorithm_combo.currentText()
            key_name = self.text_key_combo.currentText()
            
            if not key_name:
                QMessageBox.warning(self, "警告", "请选择密钥")
                return
            
            if self.text_symmetric_radio.isChecked():
                # 对称解密
                key = self.key_manager.get_symmetric_key(key_name)
                plaintext = self.symmetric_crypto.decrypt(ciphertext, key, algorithm)
            else:
                # 非对称解密
                private_key = self.key_manager.get_private_key(key_name)
                plaintext = self.asymmetric_crypto.decrypt(ciphertext, private_key, algorithm)
            
            self.text_input.setPlainText(plaintext)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")
    
    def clear_text(self):
        """清空文本"""
        self.text_input.clear()
        self.text_output.clear()
    
    def encrypt_file(self):
        """加密文件"""
        try:
            input_file = self.file_path_edit.text()
            if not input_file:
                QMessageBox.warning(self, "警告", "请选择要加密的文件")
                return
            
            # 选择输出文件
            output_file, _ = QFileDialog.getSaveFileName(self, "保存加密文件", "", 
                                                        "加密文件 (*.enc)")
            if not output_file:
                return
            
            algorithm = self.file_algorithm_combo.currentText()
            key_name = self.file_key_combo.currentText()
            
            if not key_name:
                QMessageBox.warning(self, "警告", "请选择密钥")
                return
            
            # 设置进度条
            self.file_progress.setValue(0)
            
            if self.file_symmetric_radio.isChecked():
                # 对称加密
                key = self.key_manager.get_symmetric_key(key_name)
                self.file_crypto.encrypt_file(input_file, output_file, key, algorithm, 'symmetric')
            else:
                # 非对称加密
                public_key = self.key_manager.get_public_key(key_name)
                self.file_crypto.encrypt_file(input_file, output_file, public_key, algorithm, 'asymmetric')
            
            self.file_progress.setValue(100)
            QMessageBox.information(self, "成功", "文件加密成功")
            
        except Exception as e:
            self.file_progress.setValue(0)
            QMessageBox.critical(self, "错误", f"文件加密失败: {str(e)}")
    
    def decrypt_file(self):
        """解密文件"""
        try:
            input_file = self.file_path_edit.text()
            if not input_file:
                QMessageBox.warning(self, "警告", "请选择要解密的文件")
                return
            
            # 选择输出文件
            output_file, _ = QFileDialog.getSaveFileName(self, "保存解密文件", "", 
                                                        "所有文件 (*)")
            if not output_file:
                return
            
            algorithm = self.file_algorithm_combo.currentText()
            key_name = self.file_key_combo.currentText()
            
            if not key_name:
                QMessageBox.warning(self, "警告", "请选择密钥")
                return
            
            # 设置进度条
            self.file_progress.setValue(0)
            
            if self.file_symmetric_radio.isChecked():
                # 对称解密
                key = self.key_manager.get_symmetric_key(key_name)
                self.file_crypto.decrypt_file(input_file, output_file, key, algorithm, 'symmetric')
            else:
                # 非对称解密
                private_key = self.key_manager.get_private_key(key_name)
                self.file_crypto.decrypt_file(input_file, output_file, private_key, algorithm, 'asymmetric')
            
            self.file_progress.setValue(100)
            QMessageBox.information(self, "成功", "文件解密成功")
            
        except Exception as e:
            self.file_progress.setValue(0)
            QMessageBox.critical(self, "错误", f"文件解密失败: {str(e)}")
    
    def encrypt_data(self):
        """加密数据"""
        try:
            input_file = self.data_path_edit.text()
            if not input_file:
                QMessageBox.warning(self, "警告", "请选择要加密的数据文件")
                return
            
            # 选择输出文件
            output_file, _ = QFileDialog.getSaveFileName(self, "保存加密数据", "", 
                                                        "Excel文件 (*.xlsx);;CSV文件 (*.csv)")
            if not output_file:
                return
            
            algorithm = self.data_algorithm_combo.currentText()
            key_name = self.data_key_combo.currentText()
            
            if not key_name:
                QMessageBox.warning(self, "警告", "请选择密钥")
                return
            
            key = self.key_manager.get_symmetric_key(key_name)
            
            # 设置进度条
            self.data_progress.setValue(0)
            
            if self.data_full_radio.isChecked():
                # 全表加密
                self.structured_crypto.encrypt_data(input_file, output_file, key, algorithm, 'full')
            elif self.data_column_radio.isChecked():
                # 列加密
                selected_columns = [item.text() for item in self.column_list.selectedItems()]
                if not selected_columns:
                    QMessageBox.warning(self, "警告", "请选择要加密的列")
                    return
                self.structured_crypto.encrypt_data(input_file, output_file, key, algorithm, 'column', columns=selected_columns)
            elif self.data_field_radio.isChecked():
                # 字段加密
                selected_columns = [item.text() for item in self.column_list.selectedItems()]
                if not selected_columns:
                    QMessageBox.warning(self, "警告", "请选择要加密的列")
                    return
                
                # 简单的字段选择（这里选择第一行作为示例）
                fields = [f"0,{col}" for col in selected_columns]
                self.structured_crypto.encrypt_data(input_file, output_file, key, algorithm, 'field', fields=fields)
            
            self.data_progress.setValue(100)
            QMessageBox.information(self, "成功", "数据加密成功")
            
        except Exception as e:
            self.data_progress.setValue(0)
            QMessageBox.critical(self, "错误", f"数据加密失败: {str(e)}")
    
    def decrypt_data(self):
        """解密数据"""
        try:
            input_file = self.data_path_edit.text()
            if not input_file:
                QMessageBox.warning(self, "警告", "请选择要解密的数据文件")
                return
            
            # 选择输出文件
            output_file, _ = QFileDialog.getSaveFileName(self, "保存解密数据", "", 
                                                        "Excel文件 (*.xlsx);;CSV文件 (*.csv)")
            if not output_file:
                return
            
            algorithm = self.data_algorithm_combo.currentText()
            key_name = self.data_key_combo.currentText()
            
            if not key_name:
                QMessageBox.warning(self, "警告", "请选择密钥")
                return
            
            key = self.key_manager.get_symmetric_key(key_name)
            
            # 设置进度条
            self.data_progress.setValue(0)
            
            if self.data_full_radio.isChecked():
                # 全表解密
                self.structured_crypto.decrypt_data(input_file, output_file, key, algorithm, 'full')
            elif self.data_column_radio.isChecked():
                # 列解密
                selected_columns = [item.text() for item in self.column_list.selectedItems()]
                if not selected_columns:
                    QMessageBox.warning(self, "警告", "请选择要解密的列")
                    return
                self.structured_crypto.decrypt_data(input_file, output_file, key, algorithm, 'column', columns=selected_columns)
            elif self.data_field_radio.isChecked():
                # 字段解密
                selected_columns = [item.text() for item in self.column_list.selectedItems()]
                if not selected_columns:
                    QMessageBox.warning(self, "警告", "请选择要解密的列")
                    return
                
                # 简单的字段选择（这里选择第一行作为示例）
                fields = [f"0,{col}" for col in selected_columns]
                self.structured_crypto.decrypt_data(input_file, output_file, key, algorithm, 'field', fields=fields)
            
            self.data_progress.setValue(100)
            QMessageBox.information(self, "成功", "数据解密成功")
            
        except Exception as e:
            self.data_progress.setValue(0)
            QMessageBox.critical(self, "错误", f"数据解密失败: {str(e)}")
    
    def generate_key(self):
        """生成密钥"""
        try:
            key_name = self.key_name_edit.text().strip()
            if not key_name:
                QMessageBox.warning(self, "警告", "请输入密钥名称")
                return
            
            algorithm = self.key_algorithm_combo.currentText()
            
            if self.key_symmetric_radio.isChecked():
                # 生成对称密钥
                self.key_manager.generate_symmetric_key(key_name, algorithm)
            else:
                # 生成非对称密钥对
                key_length = int(self.key_length_combo.currentText())
                self.key_manager.generate_asymmetric_key_pair(key_name, algorithm, key_length)
            
            self.update_key_lists()
            self.key_name_edit.clear()
            QMessageBox.information(self, "成功", "密钥生成成功")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"密钥生成失败: {str(e)}")
    
    def import_key(self):
        """导入密钥"""
        try:
            key_name = self.key_name_edit.text().strip()
            if not key_name:
                QMessageBox.warning(self, "警告", "请输入密钥名称")
                return
            
            # 选择导入文件
            import_file, _ = QFileDialog.getOpenFileName(self, "选择密钥文件", "", 
                                                         "JSON文件 (*.json)")
            if not import_file:
                return
            
            self.key_manager.import_key(key_name, import_file)
            self.update_key_lists()
            self.key_name_edit.clear()
            QMessageBox.information(self, "成功", "密钥导入成功")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"密钥导入失败: {str(e)}")
    
    def export_key(self):
        """导出密钥"""
        try:
            # 获取选中的密钥
            current_row = self.key_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "警告", "请选择要导出的密钥")
                return
            
            key_name = self.key_table.item(current_row, 0).text()
            
            # 选择导出文件
            export_file, _ = QFileDialog.getSaveFileName(self, "保存密钥文件", "", 
                                                        "JSON文件 (*.json)")
            if not export_file:
                return
            
            self.key_manager.export_key(key_name, export_file)
            QMessageBox.information(self, "成功", "密钥导出成功")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"密钥导出失败: {str(e)}")
    
    def delete_key(self):
        """删除密钥"""
        try:
            # 获取选中的密钥
            current_row = self.key_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "警告", "请选择要删除的密钥")
                return
            
            key_name = self.key_table.item(current_row, 0).text()
            
            # 确认删除
            reply = QMessageBox.question(self, "确认", f"确定要删除密钥 '{key_name}' 吗？")
            if reply != QMessageBox.Yes:
                return
            
            self.key_manager.delete_key(key_name)
            self.update_key_lists()
            QMessageBox.information(self, "成功", "密钥删除成功")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"密钥删除失败: {str(e)}")

def main():
    """主函数"""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()