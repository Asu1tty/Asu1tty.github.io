---
date: '2025-04-01T11:20:50+08:00'
draft: false
title: 'scoop命令合集'
tags:
  - scoop
categories:
  - softwares
---

## 1. 激活 Windows


```powershell
irm https://massgrave.dev/get | iex
```

选择 1

## 2. 安装禁止更新的 Chrome 浏览器

+ 链接：[https://pan.baidu.com/s/1Z4ZYuzWKuCoiInW9aVzszg](https://pan.baidu.com/s/1Z4ZYuzWKuCoiInW9aVzszg)  提取码：`dg0w`
+ 打开 chrome 所在位置，新建一个 `Update` 文件夹，并拒绝所有权限
  ![[Pasted image 20240222214033.png]]

## 3. 安装最新版 powershell

[Powershell releases](https://github.com/PowerShell/PowerShell/releases)

### 3.1. 关闭更新提示

```
POWERSHELL_UPDATECHECK
```

![Pasted image 20240223095124](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@main/picSource/Powershell_dis_update.png)

## 4. 安装 Windows Terminal 

+ 直接打开 Microsaft Store 搜索 `Windows Terminal` 下载即可

## 5. 安装 scoop 及插件 [[SCOOP命令]]

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

### 5.1. 安装 git

```powershell
scoop install git
```

### 5.2. 安装 gsudo

```powershell
scoop install gsudo
```

添加 `bucket`

```powershell
scoop bucket add version
scoop bucket add extras
```

### 5.3. 使用 scoop 安装 oh-my-posh

```powershell
scoop install oh-my-posh
```

#### 5.3.1. 安装 oh-my-posh 字体

```powershell
oh-my-posh font install
```

**选择 Meslo**

![Pasted image 20240222192123](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@main/picSource/Select_meslo_font.png)

选择 cascadia mono

![Pasted image 20240222192218](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@main/picSource/Select_cas_font.png)


#### 5.3.2. 配置终端的 settings. Json 文件

在 `Windows Terminal` 使用 `CTRL + SHIFT + ,` 打开 settings. Json 文件，并且找到 profiles, 配置如下

```
{
    "profiles":
    {
        "defaults":
        {
            "font":
            {
                "face": "Cascadia Mono NF"
            }
        }
    }
}
```

下面是整个 settings. Json 文件

```json
{
    "$help": "https://aka.ms/terminal-documentation",
    "$schema": "https://aka.ms/terminal-profiles-schema",
    "actions": [],
    "copyFormatting": "none",
    "copyOnSelect": false,
    "defaultProfile": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
    "initialCols": 65,
    "initialPosition": "40,50",
    "initialRows": 27,
    "keybindings": 
    [
        {
            "id": "Terminal.CopyToClipboard",
            "keys": "ctrl+c"
        },
        {
            "id": "Terminal.FindText",
            "keys": "ctrl+shift+f"
        },
        {
            "id": "Terminal.PasteFromClipboard",
            "keys": "ctrl+v"
        },
        {
            "id": "Terminal.DuplicatePaneAuto",
            "keys": "alt+shift+d"
        }
    ],
    "newTabMenu": 
    [
        {
            "type": "remainingProfiles"
        }
    ],
    "profiles": 
    {
        "defaults": 
        {
            "colorScheme": "OneHalfDark modded",
            "font": 
            {
                "face": "Cascadia Mono NF"
            },
            "opacity": 45,
            "useAcrylic": true
        },
        "list": 
        [
            {
                "commandline": "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "guid": "{61c54bbd-c2c6-5271-96e7-009a87ff44bf}",
                "hidden": false,
                "name": "Windows PowerShell"
            },
            {
                "commandline": "%SystemRoot%\\System32\\cmd.exe",
                "guid": "{0caa0dad-35be-5f56-a8ff-afceeeaa6101}",
                "hidden": false,
                "name": "\u547d\u4ee4\u63d0\u793a\u7b26"
            },
            {
                "guid": "{b453ae62-4e3d-5e58-b989-0a998ec441b8}",
                "hidden": false,
                "name": "Azure Cloud Shell",
                "source": "Windows.Terminal.Azure"
            },
            {
                "guid": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
                "hidden": false,
                "name": "PowerShell",
                "source": "Windows.Terminal.PowershellCore"
            },
            {
                "commandline": "%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy ByPass -NoExit -Command \"& 'D:\\Scoop\\apps\\miniconda3\\25.5.1-1\\shell\\condabin\\conda-hook.ps1' ; conda activate 'D:\\Scoop\\apps\\miniconda3\\25.5.1-1' \"",
                "guid": "{439f9f7a-c0f9-5788-9a1d-3aae5085aeda}",
                "icon": "D:\\Scoop\\apps\\miniconda3\\25.5.1-1\\Menu\\anaconda_powershell_prompt.ico",
                "name": "Anaconda PowerShell Prompt (25.5.1-1)",
                "startingDirectory": "C:\\Users\\wiegc"
            },
            {
                "commandline": "%WINDIR%\\System32\\cmd.exe \"/K\" D:\\Scoop\\apps\\miniconda3\\25.5.1-1\\Scripts\\activate.bat D:\\Scoop\\apps\\miniconda3\\25.5.1-1",
                "guid": "{6d8965e3-9f63-523d-a1a8-b62076fc0e09}",
                "icon": "D:\\Scoop\\apps\\miniconda3\\25.5.1-1\\Menu\\anaconda_prompt.ico",
                "name": "Anaconda Prompt (25.5.1-1)",
                "startingDirectory": "C:\\Users\\wiegc"
            }
        ]
    },
    "schemes": 
    [
        {
        "name": "OneHalfDark modded",
        "black": "#282c34",
        "red": "#e06c75",
        "green": "#98c379",
        "yellow": "#e5c07b",
        "blue": "#61afef",
        "purple": "#c678dd",
        "cyan": "#56b6c2",
        "white": "#dcdfe4",
        "brightBlack": "#282c34",
        "brightRed": "#e06c75",
        "brightGreen": "#98c379",
        "brightYellow": "#e5c07b",
        "brightBlue": "#61afef",
        "brightPurple": "#c678dd",
        "brightCyan": "#56b6c2",
        "brightWhite": "#dcdfe4",
        "background": "#001B26",
        "foreground": "#dcdfe4",
        "selectionBackground": "#474e5d",
        "cursorColor": "#a3b3cc"
        }
    ],
    "themes": [],
    "useAcrylicInTabRow": true
}
```



### 5.4. 配置 oh-my-posh 主题

#### 5.4.1. 下载 json 主题

[下载Json主题](https://github.com/JanDeDobbeleer/oh-my-posh/blob/main/themes/json.omp.json)

保存到 `D:\Scoop\theme\json.omp.json`

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

下面是整个$PROFILE 文件

```$PROFILE
#------------------------------- Import Modules BEGIN -------------------------------

Import-Module 'gsudoModule'
Invoke-Expression (&scoop-search --hook)
#StarShip配置
Invoke-Expression (&starship init powershell)
#Oh-My-Posh配置
#oh-my-posh init pwsh --config 'D:\Scoop\theme\json.omp.json' | Invoke-Expression

#------------------------------- Import Modules END   --------------------------------

#-------------------------------  Set Hot-keys BEGIN  ---------------------------------

# 设置预测文本来源为历史记录
Set-PSReadLineOption -PredictionSource History

# 每次回溯输入历史，光标定位于输入内容末尾
Set-PSReadLineOption -HistorySearchCursorMovesToEnd

# 设置 Tab 为菜单补全和 Intellisense
Set-PSReadLineKeyHandler -Key "Tab" -Function MenuComplete

# 设置 Ctrl+d 为退出 PowerShell
Set-PSReadlineKeyHandler -Key "Ctrl+d" -Function ViExit

# 设置 Ctrl+z 为撤销
Set-PSReadLineKeyHandler -Key "Ctrl+z" -Function Undo

# 设置向上键为后向搜索历史记录
Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward

# 设置向下键为前向搜索历史纪录
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward

# 启用预测性 IntelliSense
# Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView

#-------------------------------  Set Hot-keys END    -------------------------------


#-------------------------------   Set Alias BEGIN    -------------------------------

# 3. 查看目录 ls & ll
function ListDirectory {
	(Get-ChildItem).Name
	Write-Host("")
}
Set-Alias -Name ls -Value ListDirectory
Set-Alias -Name ll -Value Get-ChildItem
Set-Alias grep findstr

#-------------------------------    Set Alias END     -------------------------------
```



#### 5.4.3. 完成配置

```powershell
. $PROFILE
```



#### 5.4.4. 加快 powershell 启动速度（可选）

在安装 `miniconda` 后，会因为 `conda init` 导致启动速度降低，所以可以使用下面代码加快速度

先使用命令查看路径

```powershell
$PROFILE
```

然后具体替换 `profile.ps1` 或者 `Microsoft.PowerShell_profile.ps1` 中的内容，一般是 `profile.ps1`



```ps1
#region conda initialize
# !! Contents within this block are managed by 'conda init' !!
#region conda initialize
$global:CondaInitialized = $false

# 保证powershell加载速度
function Initialize-Conda {
    if (-not $global:CondaInitialized) {
        if (Test-Path "D:\Scoop\apps\miniconda3\current\Scripts\conda.exe") {
            $condaHook = & "D:\Scoop\apps\miniconda3\current\Scripts\conda.exe" "shell.powershell" "hook"
            $condaHook | Out-String | Invoke-Expression
            $global:CondaInitialized = $true
            Write-Host "Conda initialized" -ForegroundColor Green
        }
    }
}

# 修复vscode虚拟环境无法conda init
function activate { 
    param([string]$env)
    Initialize-Conda
    if ($env) { 
        conda activate $env 
    } else {
        Write-Host "Usage: activate <environment_name>"
    }
}
#endregion
```



### 5.5. 配置 vscode 终端的字体

#### 5.5.1. 

```
"terminal.integrated.fontFamily": "CaskaydiaMono Nerd Font",
```

#### 5.5.2. 

完整 vscode 配置

```json
{
    "editor.fontSize": 19,
    "[javascript]": {
        "editor.maxTokenizationLineLength": 2500
    },
    "workbench.colorTheme": "GitHub Clean White",
    "files.autoGuessEncoding": true,
    "editor.tabCompletion": "on",
    "security.workspace.trust.enabled": false,
    "editor.formatOnSave": true,
    "editor.formatOnPaste": true,
    "editor.formatOnType": true,
    "terminal.integrated.fontFamily": "Cascadia Mono NF",
    "editor.fontFamily": "Cascadia Mono NF, '微软雅黑', monospace",
    "files.autoSave": "afterDelay",
    "workbench.list.smoothScrolling": true,
    "editor.cursorSmoothCaretAnimation": "on",
    "editor.smoothScrolling": true,
    "editor.cursorBlinking": "smooth",
    "editor.mouseWheelZoom": true, //滚轮调节字体大小
    "editor.wordWrap": "on",
    "editor.acceptSuggestionOnEnter": "smart",
    "editor.suggestSelection": "recentlyUsed",
    "window.dialogStyle": "custom",
    "debug.showBreakpointsInOverviewRuler": true,
    "editor.acceptSuggestionOnCommitCharacter": false,

    "code-runner.runInTerminal": true,
    "code-runner.saveAllFilesBeforeRun": true,
    "code-runner.saveFileBeforeRun": true
    
}
```





## 6. 修改 vscode 默认字体

### 6.1. 下载字体

[字体大全](https://github.com/ryanoasis/nerd-fonts)

[Cascadia Code](https://github.com/microsoft/cascadia-code/releases/tag/v2111.01)

[FiraCode](https://github.com/tonsky/FiraCode/releases/tag/6.2)

[Meslo-Font](https://github.com/andreberg/Meslo-Font)

### 6.2. 安装字体

**全选 ttf 后缀文件安装**
![Pasted image 20240222201514](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@main/picSource/install_ttf.png)

## 7. 安装 WLS 2

[微软官方安装](https://learn.microsoft.com/zh-cn/windows/wsl/install-manual)

### 7.1. 启用适用于 Linux 的 Windows 子系统

```PowerShell
Dism. Exe /online /enable-feature /featurename: Microsoft-Windows-Subsystem-Linux /all /norestart
```

### 7.2. 检查运行 WSL 2 的要求

对于 win 10，版本 1903 或更高版本

### 7.3. 启用虚拟机功能

```powershell
Dism. Exe /online /enable-feature /featurename: VirtualMachinePlatform /all /norestart
```

### 7.4. 下载 Linux 内核更新包

[适用于 x64 计算机的 WSL2 Linux 内核更新包](https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi)

### 7.5. 将 WSL 2 设置为默认版本

```powershell
Wsl --set-default-version 2
```

### 7.6. 安装所选的 Linux 分发

打开 Windows Store 安装 Ubuntu 22.04 或其他版本

## 8. 安装百度网盘

### 8.1. 下载百度网盘

已知百度云 PC 客户端的官网下载链接是：https://issuepcdn.baidupcs.com/issue/netdisk/yunguanjia/BaiduNetdisk_X.X.X.X.exe；

然后使用百度云官网的历史版本页面：
https://pan.baidu.com/disk/version

在里面找到需要的版本号后，按上面链接的格式将官网下载链接补充完整，即可下载。

也可以使用其他网站总结的历史版本号，补全后下载。如最后一个未添加工作空间的、大小“仅”66 mb 的 7.2.8.9 版本，就可以将X.X.X.X 替换为 7.2.8.9 后回车，即可下载。
[点击下载7.27.1.5版本](https://issuepcdn.baidupcs.com/issue/netdisk/yunguanjia/BaiduNetdisk_7.27.1.5.exe)

### 8.2. 防止百度网盘更新

#### 8.2.1. 找到百度网盘安装目录

在电脑桌面百度网盘快捷方式上点 “右键”，点`打开文件所在的位置`。

#### 8.2.2. 找到自动升级组件

+ 找到文件夹 `AutoUpdate`, 删除内容并在安全中修改访问权限为拒绝。
+ 找到`autoDiagnoseUpdate. Exe`删除并创建空 txt 命名为`autoDiagnoseUpdate. Exe`, 修改读取写入权限为拒绝。
+ 找到`kernelUpdate. Exe`删除并创建空 txt 命名为`kernelUpdate. Exe`, 修改读取写入权限为拒绝。





# 参考

[Windows Terminal 完美配置 PowerShell 7.1](https://zhuanlan.zhihu.com/p/137595941)
[oh-my-posh](https://ohmyposh.dev/docs/installation/windows)
