# Lurk

后们绑定命令行/GUI工具。

## FEATURE

- 支持x86架构32位PE程序
- 采用模块化开发（目前GUI只封装了downloadAndExec的功能）
- 功能代码支持以asm/bin/C/dll等形式开发
- 以拓展section的形式增加shellcode
- 支持XOR SMC
- 跨平台

## AV bypass List

欢迎反馈并更新杀软测试结果

- [x] 360
- [x] KasperSky
- [x] Windows Defender
- [x] 火绒

## Getting Start

### Installation

首先你至少要有64位Python，推荐使用python2.7，你可以从[这里](https://www.python.org/downloads/release/python-2714/)选择你需要的版本并下载。

安装python时，勾选`pip`与`Add python.exe to Path`

![python_install](resource/python_install.png)

用pip安装依赖包

**pip源慢的可以切换国内源**

创建`pip.ini`文件在如下路径`C:\Users\XXX\pip\pip.ini`，并修改内容为

```
[global]
index-url = http://mirrors.aliyun.com/pypi/simple/
[install]
trusted-host = mirrors.aliyun.com
```

结束后首先

`pip install setuptools --upgrade`

`pip install -r requestments.txt`

#### Troubleshooting

`error: can't copy 'src\build\capstone.dll': doesn't exist or not a regular file`

直接下载capstone的[二进制编译文件](https://github.com/aquynh/capstone/releases/download/3.0.5-rc2/capstone-3.0.5-rc2-python-win64.msi)

`error: can't copy 'src\build\llvm\lib\libkeystone.so': doesn't exist or not a regular file`

下载keystone的[二进制编译文件](https://github.com/keystone-engine/keystone/releases/download/0.9.1/keystone-0.9.1-python-win64.msi)

`Exception: Unable to find C:\Users\ree/lief-0.8.3-py2.7-windows_x64.egg`

pip安装lief`pip install lief`

### Usage

*目前只提供GUI界面的使用文档*

主界面

![main](resource/main.png)

菜单栏中，`Lurk`可以得到Help/About信息，Help可以打开本`README.md`文档

`Url`

该变量定义将下载的目标文件的Url地址，必须以`http://`或`https://`开头。推荐使用如[github.com](github.com)等公知安全的域名，为目标文件下载地址；不推荐使用ip定位的方式。

`Filename`

目标文件，使用`browser`按钮进行填充。

`Address`

patch地址，需要使用者手动确定，后续将自动化该功能。值得注意的是，该地址需要满足以下几个条件。

1. 尽量避免地址出现在循环中。因为我们没有设置shellcode的执行次数，一旦出现在循环中，shellcode将被执行多次，出现不可预计的情况。
2. 尽量避免出现在开头或结尾。开头与结尾是AV的重点检查地址，出现在开头可能会引起AV的警报。
3. patch地址的指令长度必须为5.

`Download Filename`

下载文件的保存名称。如`calc.exe`

`Debug info`

右侧为patch过程中，相关信息的log。

patch后因为调用了我自己写的dll，将`Lurk\shellcode\dll\downloader.dll`拷贝致同一目录。

## Task list

- [ ] 支持x86架构64位
- [ ] 支持ELF,Mach-O
- [ ] 实现code cave jump方式添加shellcode
- [ ] 实现新加section方式增加shellcode
- [ ] 自动化寻找可以patch的地址，并测试
- [ ] 添加功能dll
- [ ] 丰富SMC加密算法，如增加AES/DES
- [ ] 完善log信息
- [ ] 实现控制台功能，前端增加控制界面
- [ ] 增加加密通讯功能
- [ ] 添加C/S或者B/S架构，前端只有GUi，功能代码全部放入后端
- [ ] 美化界面
- [ ] 完全模块化

## Development

### Class `class LurkGUI(object)`

为GUI而封装的类。

### Class `class LurkPyQt5(QMainWindows)`

`PyQt5`实现的前端界面。

### Class `class LurkMain(object)`

命令行处理类。

### Class `class Pebin(object)`

`class Pebin(object)`是主要的逻辑实现类，添加新的功能定义私有方法即可。

`self.do_patch(self, filename)`调用`Patcher.inject(raw)`与`Patcher.patch()`进行patch。

### Class `class Patcher(object)`

`class Patcher(object)`是主要涉及PE文件操作的类。

### Dirctoinary `shellcode`

主要shellcode文件夹，`asm`，`dll`，`rawdata`为不同格式存储的shellcode。`tmp`为patch过程中存放的临时生成shellcode。

## Report

如果你有任何关于Bug或功能的想法，欢迎与我联系。`heyuanree@gmail.com`

## Changelog

- V-0.1 0.1版本发布
- V-0.1.1 增加GUI版本的自动探测可patch地址的功能
- V-0.1.2 增加线程功能，前端界面不再出现假死