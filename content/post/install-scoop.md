---
date: '2025-04-01T11:20:50+08:00'
draft: false
title: 'scoop命令合集'
tags:
  - scoop
categories:
  - softwares
---

## 1. 激活Windows


```powershell
irm https://massgrave.dev/get | iex
```

选择1
## 2. 安装禁止更新的Chrome浏览器

+ 链接：[https://pan.baidu.com/s/1Z4ZYuzWKuCoiInW9aVzszg](https://pan.baidu.com/s/1Z4ZYuzWKuCoiInW9aVzszg)  提取码：`dg0w`
+ 打开chrome所在位置，新建一个`Update`文件夹，并拒绝所有权限
  ![[Pasted image 20240222214033.png]]

## 3. 安装最新版powershell

[Powershell releases](https://github.com/PowerShell/PowerShell/releases

### 3.1. 关闭更新提示

```
POWERSHELL_UPDATECHECK
```

![[Pasted image 20240223095124.png]]

## 4. 安装Windows Terminal 

+ 直接打开 Microsaft Store 搜索 `Windows Terminal` 下载即可
## 5. 安装scoop及插件[[SCOOP命令]]

```powershell
[Environment]::SetEnvironmentVariable('SCOOP', 'D:\Scoop', 'User');
[Environment]::SetEnvironmentVariable('SCOOP_GLOBAL', 'D:\Scoop-Global', 'Machine');
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser;
irm get.scoop.sh | iex
```

如果最后一句不行则替换为
```powershell
iex "& {$(irm get.scoop.sh)} -RunAsAdmin"
```

### 5.1. 安装git
```powershell
scoop install git
```

### 5.2. 安装gsudo

```powershell
scoop install gsudo
```
### 5.3. 使用scoop安装oh-my-posh
```powershell
scoop install https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/oh-my-posh.json
```

#### 5.3.1. 安装oh-my-posh字体
```powershell
oh-my-posh font install
```

**选择Meslo**

![[Pasted image 20240222192123.png]]

选择cascadia mono

![[Pasted image 20240222192218.png]]


#### 5.3.2. 配置终端的settings.json文件
在`Windows Terminal`使用`CTRL + SHIFT + ,`打开settings.json文件，并且找到profiles,配置如下
```
{
    "profiles":
    {
        "defaults":
        {
            "font":
            {
                "face": "MesloLGM Nerd Font"
            }
        }
    }
}
```

下面是整个settings.json文件

[[Windows Terminal settings.json]]
### 5.4. 配置oh-my-posh主题
#### 5.4.1. 下载json主题

[下载Json主题](https://github.com/JanDeDobbeleer/oh-my-posh/blob/main/themes/json.omp.json)

保存到`D:\Scoop\theme\json.omp.json`
#### 5.4.2. 设置配置文件
```
notepad $PROFILE
```
**如果打开文件无法保存则先使用下面的命令**
```
New-Item -Path $PROFILE -Type File -Force
```
**在配置文件中加入下面一行**
```
oh-my-posh init pwsh --config 'D:\Scoop\theme\json.omp.json' | Invoke-Expression
```

下面是整个$PROFILE文件

[[$PROFILE]]
#### 5.4.3. 完成配置
```powershell
. $PROFILE
```

### 5.5. 配置vscode终端的字体
#### 5.5.1. 
```
"terminal.integrated.fontFamily": "CaskaydiaMono Nerd Font",
```

## 6. 修改vscode默认字体
### 6.1. 下载字体

[字体大全](https://github.com/ryanoasis/nerd-fonts)

[Cascadia Code](https://github.com/microsoft/cascadia-code/releases/tag/v2111.01)

[[FiraCode](https://github.com/tonsky/FiraCode)](https://github.com/tonsky/FiraCode/releases/tag/6.2)

[[Meslo-Font](https://github.com/andreberg/Meslo-Font)](https://github.com/andreberg/Meslo-Font)

### 6.2. 安装字体

**全选ttf后缀文件安装**
![[Pasted image 20240222201514.png]]

## 7. 安装WLS2

[微软官方安装](https://learn.microsoft.com/zh-cn/windows/wsl/install-manual)
### 7.1. 启用适用于 Linux 的 Windows 子系统

```PowerShell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
```

### 7.2. 检查运行 WSL 2 的要求

对于win10，版本 1903 或更高版本

### 7.3. 启用虚拟机功能

```powershell
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

### 7.4. 下载 Linux 内核更新包

[适用于 x64 计算机的 WSL2 Linux 内核更新包](https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi)

### 7.5. 将 WSL 2 设置为默认版本

```powershell
wsl --set-default-version 2
```

### 7.6. 安装所选的 Linux 分发

打开Windows Store 安装Ubuntu22.04或其他版本

## 8. 安装百度网盘
### 8.1. 下载百度网盘

已知百度云PC客户端的官网下载链接是：https://issuepcdn.baidupcs.com/issue/netdisk/yunguanjia/BaiduNetdisk_X.X.X.X.exe；

然后使用百度云官网的历史版本页面：
https://pan.baidu.com/disk/version

在里面找到需要的版本号后，按上面链接的格式将官网下载链接补充完整，即可下载。

也可以使用其他网站总结的历史版本号，补全后下载。如最后一个未添加工作空间的、大小“仅”66mb的7.2.8.9版本，就可以将X.X.X.X替换为7.2.8.9后回车，即可下载。
[点击下载7.27.1.5版本](https://issuepcdn.baidupcs.com/issue/netdisk/yunguanjia/BaiduNetdisk_7.27.1.5.exe)
### 8.2. 防止百度网盘更新
#### 8.2.1. 找到百度网盘安装目录

在电脑桌面百度网盘快捷方式上点 “右键”，点`打开文件所在的位置`。
#### 8.2.2. 找到自动升级组件
+ 找到文件夹 `AutoUpdate`,删除内容并在安全中修改访问权限为拒绝。
+ 找到`autoDiagnoseUpdate.exe`删除并创建空txt命名为`autoDiagnoseUpdate.exe`,修改读取写入权限为拒绝。
+ 找到`kernelUpdate.exe`删除并创建空txt命名为`kernelUpdate.exe`,修改读取写入权限为拒绝。
### 8.3. 下载Cheat Engine







# 参考

[# Windows Terminal 完美配置 PowerShell 7.1](https://zhuanlan.zhihu.com/p/137595941)
[oh-my-posh](https://ohmyposh.dev/docs/installation/windows)
