# VulExplorer
基于加权特征依赖图的C语言源代码漏洞检测系统  
C language source code vulnerability detection system based on weighted feature dependency graph  
## 环境依赖
操作系统: 
* Linux Ubuntu >=18.04  

程序依赖:  
* clang 9.0.0
* LLVM
* Git
* CMake >=3.14
* Python >=3.6

## 初始化配置
```shell
./config.sh
```

## 漏洞集获取和生成
```shell
cd ./crawl_vuls
python3 run_spider.py
python3 gen_dataset.py
```

## 系统命令
* `dataset show`: 输出漏洞集信息
* `dataset check`: 选择用于检测的数据集
* `config show`: 输出当前配置信息
* `config set`: 设置运行时配置信息
* `detect`: 进行漏洞检测
* `help`: 帮助信息, 即上述命令的具体用法

## 运行系统
```shell
python3 main.py
```
或者
```shell
python3 main.py <cmd_and_args>
```

## 参考项目
[leontsui1987/VulDetector: A static-analysis tool to detect C/C++ vulnerabilities based on graph comparison](https://github.com/leontsui1987/VulDetector)
