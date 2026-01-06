#!/usr/bin/env python3
"""
综合加密系统启动器
启动图形界面进行加密操作
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from main import MainWindow

def main():
    """主函数"""
    print("正在启动综合加密系统...")
    print("支持的加密算法：")
    print("- 对称加密：SM4、AES、3DES")
    print("- 非对称加密：RSA、ECC")
    print("- 支持文件加密和结构化数据加密")
    print("- 完整的密钥管理系统")
    print("- 支持Excel、CSV文件加密")
    print("=" * 50)
    
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    
    print("系统启动成功！")
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()