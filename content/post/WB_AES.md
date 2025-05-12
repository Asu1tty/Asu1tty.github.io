---
date: '2025-04-24T21:10:36+08:00'
draft: false
title: 'AES原理及白盒AES的DFA攻击'
tags:
  - AES
  - Hash
categories:
  - Crypto
---

AES（**Advanced Encryption Standard**） **高级加密标准**是 Rijndael [分组密码](https://en.wikipedia.org/wiki/Block_cipher "Block cipher")  的一种变体，由两位密码学家 [Joan Daemen](https://en.wikipedia.org/wiki/Joan_Daemen "Joan Daemen") 和 [Vincent Rijmen](https://en.wikipedia.org/wiki/Vincent_Rijmen "Vincent Rijmen") 开发，他们在 [AES 选择过程中](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard_process "Advanced Encryption Standard process")向 NIST 提交了一份提案Rijndael 是一系列具有不同密钥和块大小的密码。对于 AES，NIST 选择了 Rijndael 家族的三个成员，每个成员的块大小为 128 位，但有三种不同的密钥长度：128、192 和 256 位。
## 1. AES分类

| 分类    | 密钥长度 | 轮密钥长度 | 扩展密钥长度 | 分组长度 | 加密轮数 |
| ------- | -------- | ---------- | ------------ | -------- | -------- |
| AES-128 | 16字节   | 16字节     | 16*11=172    | 16字节   | 10       |
| AES-192 | 24字节   | 16字节     | 16*13=208    | 16字节   | 12       |
| AES-256 | 32字节   | 16字节     | 16*15=240    | 16字节   | 14       |



AES 128 192 256 除了密钥编排算法不一样和加密轮数不一样 其余的计算逻辑相同

AES 128 192 256 CBC 模式IV的长度都是16个字节 CBC计算逻辑相同

AES-128 密钥编排中K0是原始密钥 共16个字节

AES-192 密钥编排中K0和K1前半部分是原始密钥 共24个字节

AES-256 密钥编排中K0和K1是原始密钥 共32个字节

**如非特别说明，下面加密介绍中`AES`都以`AES-128`为例**

## 2. PKCS填充方式
PKCS5填充字符串由一个1~8位的字节序列组成，每个字节填充该字节序列的长度
PKCS7（**95%** 都是PKCS7）填充字符串由一个1-255位的字节序列组成，每个字节填充该字节序列的长度
比如 AES-128的数据块长度是 16bytes，使用PKCS7进行填充时，填充的长度范围是 1 ~ 16

示例一：
数据： FF FF FF FF FF FF FF FF FF
```plaintext
PKCS5 填充： FF FF FF FF FF FF FF FF FF 07 07 07 07 07 07 07
PKCS7 填充： FF FF FF FF FF FF FF FF FF 07 07 07 07 07 07 07
```
示例二：  
数据： FF FF FF FF FF FF FF FF FF FF
```plaintext
PKCS5 填充： FF FF FF FF FF FF FF FF FF FF 06 06 06 06 06 06
PKCS7 填充： FF FF FF FF FF FF FF FF FF FF 06 06 06 06 06 06
```

**思考**：当明文恰好是：`FF FF FF FF FF FF FF FF FF FF 06 06 06 06 06 06` 时，应当如何分辨`06 06 06 06 06 06`到底是填充还是明文呢？

示例三：
明文恰好是：FF FF FF FF FF FF FF FF FF FF 06 06 06 06 06 06
```plaintext
PKCS5填充：FF FF FF FF FF FF FF FF FF FF 06 06 06 06 06 06 08 08 08 08 08 08 08 08
PKCS7填充：FF FF FF FF FF FF FF FF FF FF 06 06 06 06 06 06 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
```
PKCS7是兼容PKCS5的，PKCS5相当于PKCS7的一个子集

## 3. 加密模式
常用加密模式分为`ECB`与`CBC`，`CBC`加密模式比`ECB`加密模式多一个IV
在`ECB`模式下，将明文分成固定大小的块每个块独立加密，相同的明文块始终生成相同的密文块。

**优点**：

- 简单，易于并行处理。
- 加密和解密速度快。

**缺点**：
- 安全性较低，相同的明文块产生相同的密文块，容易受到模式分析攻击。
- 不适合加密大数据或具有重复模式的明文（如图像）。

在`CBC`模式下，每个明文块在加密前先与前一个密文块进行异或（`XOR`）操作，这时要求多一个IV的作用就来了，第一个块使用初始化向量（`IV`）。这使得相同的明文块在不同位置生成不同的密文。
**优点**：

- 安全性更高，相同的明文块不会产生相同的密文，抗模式分析能力强。
- 适合加密大数据或结构化数据。

**缺点**：
- 加密过程是串行的，无法并行化，速度稍慢。
- 需要安全的初始化向量（`IV`），且IV必须在加密和解密时保持一致。



在此附上一张经典加密Linux吉祥物企鹅位图（bitmap）格式的图片
![image.png](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250424152317564.png?raw=true)
可以看出，因为同样的颜色编码序列被加密成相同的密文，所以生成的文件重现原图的大致模式，可以大致看出企鹅的轮廓。

## 4. 计算流程
![image.png](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714394217281-9c474ec2-91c1-4ca8-b349-ccb7b6541661.png)

![image.png](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714394336630-bdece8b0-888b-45d0-b1c1-7214e58e7950.png)
AES的整体图景可以分成左右两块，即明文的处理和密钥的编排

明文的处理主体是一个初始化轮密钥加和十轮运算，在初始化轮密钥加十轮运算中都需要使用密钥编排的结果

密钥编排将16个字节经过运算推演出11组轮密钥，每一组16个字节，称之为K0，K1...K10
### 4.1. 密钥编排
假设密钥Key为： **2b7e151628aed2a6abf7158809cf4f3c**。为了区分密钥和密钥编排后的轮密钥，我们将此时的密钥叫主密钥。
在AES-128中，密钥扩展后得`16*11`共176字节，使用时**逐十六个字节**划分成K0,K1,...K10使用，但是在生成时，它是**逐四个字**节生成的，即`44*4`。我们不妨用数组来描述它，即一个包含了44个元素的数组,叫W
这四十四个元素的生成规则有三种，如下图所示
![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714394679115-935cf8de-f210-41f9-bdfe-291064ac4623.png)
不同颜色代表了不同规则

#### 4.1.1. 蓝色区域
最上方蓝色区域的就是主密钥本身切成四段![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714394811982-5f61936e-12d4-4761-8c32-91eeb366b9b1.png)
#### 4.1.2. 红色区域
左侧的红色部分，W4，W8...W40 的生成复杂一点

![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714394914198-e4b275b3-8727-4566-93b1-6f5cf0edcb16.png)

xor 是异或运算，关键点就是这个g函数了，函数一共三个步骤——**循环左移、S盒替换、字节异或**
我们以运算W4中所需的W3为例

![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714395039925-e8dd3f8e-ba46-4563-af5d-dd7b31c32a87.png)

第一步是循环左移，规则固定——将最左边的一个字节挪到右边即可

![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714395105629-7f04a502-8f4f-4693-9b8a-2f6cce3d6a7b.png)

第二步是S盒替换，S盒替换听着很高级，但操作上很简单——将数值本身作为索引取出S数组中对用的值，S 盒是固定的，在Findcrypt中，就会利用S盒来查找AES的存在
```python
SBox = [
0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8,
0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3,
0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C,
0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D,
0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E,
0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95,
0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD,
0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1,
0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54,
0xBB, 0x16
]
```
第三步骤更简单，将上一步结果中的最高字节和一个固定常量异或，W4的生成是第一个，用如下Rcon 表的第一个元素0x1，W40即第十次，用最后一个元素0x36
```python
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
```
![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714395571691-e6a61272-3fb9-4ab6-8e53-26835454635c.png)

最终结果

![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714395608655-8716d83e-7d6c-4cff-b130-c68d87d8a524.png)

上图中蓝色和红色的部分我们都讲完了，那么橙色部分呢？相当的简单，和红色部分类似，去掉g函数即可

![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714395689385-bb301b33-428f-4e37-9f4e-13ea4e8081f9.png)

打个比方， W5 = W4 ^ W1 = 0xa0fafe17 ^ 0x28aed2a6 = 0x88542cb1
如下是完整的密钥编排部分的Python代码
```python
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE,
    0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
    0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
    0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB,
    0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
    0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A,
    0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50,
    0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10,
    0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64,
    0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE,
    0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91,
    0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65,
    0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
    0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86,
    0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE,
    0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0,
    0x54, 0xBB, 0x16,
)
Rcon = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def text2matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix


def shiftRound(array, num):
    '''
    :param array: 需要循环左移的数组
    :param num: 循环左移的位数
    :return: 使用Python切片，返回循环左移num个单位的array
    '''
    return array[num:] + array[:num]


def g(array, index):
    '''
    g 函数
    :param array: 待处理的四字节数组
    :index:从1-10，每次使用Rcon中不同的数
    '''
    # 首先循环左移1位
    array = shiftRound(array, 1)
    # 字节替换
    array = [Sbox[i] for i in array]
    # 首字节和rcon中对应元素异或
    array = [(Rcon[index] ^ array[0])] + array[1:]
    return array


def xorTwoArray(array1, array2):
    '''
    返回两个数组逐元素异或的新数组
    :param array1: 一个array
    :param array2: 另一个array
    :return:
    '''
    assert len(array1) == len(array2)
    return [array1[i] ^ array2[i] for i in range(len(array1))]


def showRoundKeys(kList):
    for i in range(len(kList)):
        print("K%02d:" % i + "".join("%02x" % k for k in kList[i]))


def keyExpand(key):
    master_key = text2matrix(key)
    round_keys = [[0] * 4 for i in range(44)]
    # 规则一(图中红色部分)
    for i in range(4):
        round_keys[i] = master_key[i]
    for i in range(4, 4 * 11):
        # 规则二(图中红色部分)
        if i % 4 == 0:
            round_keys[i] = xorTwoArray(g(round_keys[i - 1], i // 4), round_keys[i - 4])
        # 规则三(图中橙色部分)
        else:
            round_keys[i] = xorTwoArray(round_keys[i - 1], round_keys[i - 4])
    # 将轮密钥从44*4转成11*16,方便后面在明文的运算里使用
    kList = [[] for i in range(11)]
    for i in range(len(round_keys)):
        kList[i // 4] += round_keys[i]
    showRoundKeys(kList)
    return kList


input_bytes = 0x00112233445566778899aabbccddeeff
key = 0x2b7e151628aed2a6abf7158809cf4f3c
kList = keyExpand(key)
```
运行结果如下
```plaintext
K00:2b7e151628aed2a6abf7158809cf4f3c
K01:a0fafe1788542cb123a339392a6c7605
K02:f2c295f27a96b9435935807a7359f67f
K03:3d80477d4716fe3e1e237e446d7a883b
K04:ef44a541a8525b7fb671253bdb0bad00
K05:d4d1c6f87c839d87caf2b8bc11f915bc
K06:6d88a37a110b3efddbf98641ca0093fd
K07:4e54f70e5f5fc9f384a64fb24ea6dc4f
K08:ead27321b58dbad2312bf5607f8d292f
K09:ac7766f319fadc2128d12941575c006e
K10:d014f9a8c9ee2589e13f0cc8b6630ca6
```

### 4.2. 10轮运算

在AES中，数据以State的形式计算、中间存储和传输，中文名即状态。从明文转到state形式很简单，以我们的明文00112233445566778899aabbccddeeff为例。从上到下，从左到右
![](https://raw.githubusercontent.com/Asu1tty/blog_img/main/picSource/1714396330904-f408437b-8456-4ed3-b404-75a5e7b91262.png)
初始的轮密钥加使用K0 2b7e151628aed2a6abf7158809cf4f3c![image.png](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714396464338-b7bb7565-b73b-4147-8e95-a1c2b9de2847.png)

接下来就是十轮主运算，看如下的伪代码，我们可以清楚看到一轮运算中有什么，以及第十轮和前九轮有什么区别  

![image.png](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714396609549-599374c9-2d16-4eef-a409-59ab2cb31235.png)

初始的明文转和最后的转明文自不必说，然后是初始轮密钥，使用K0  
前九轮运算中，包含四个步骤：**字节替换，循环左移，列混淆，轮密钥加**  
第十轮中，包含三个步骤：**字节替换，循环左移，轮密钥加，相比前九轮缺一个列混淆，其余相同**  
而字节替换步骤，和密钥编排中的S盒替换完全一致  
循环左移，和密钥编排中的循环左移类似，但有差异。密钥编排中，函数中也需循环左移，但其中待处理的数据仅有一行，而明文编排中是四行，其循环左移规则如下：第一行不循环左移，第二行循环左移1字节，第三行循环左移2字节，第四行循环左移3字节  

![image.png](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714396902808-c6c3bc24-82e1-4f07-ac7b-f618ec0647ca.png)

列混淆比较复杂  
详见[白盒AES算法详解(一)](https://bbs.kanxue.com/thread-280335.htm)

## 5. 白盒AES的DFA攻击
AES白盒加密主流的方法就是通过将原本的字节替换，行移位，列混淆和轮密钥加等操作用查表的方法实现，轮密钥则被合并到这些表中。
首先需要明确的是，可以通过轮密钥推出主密钥，这是解出白盒AES密钥的关键

![image.png](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/1714396609549-599374c9-2d16-4eef-a409-59ab2cb31235.png)
在倒数两次列混淆(mixColumns)之间的state随机修改一个字节.
也就是第9轮的subbytes和shiftRows以及第8轮的addRoundKey中的任何一个时机修改即可,一般shiftRows是比较常见的,因为比较容易看出来

修改后的异常密文和原密文可以用phoenixAES 还原出来第10轮密钥,# 第一行是正确密文 后面是故障密文,一般两百个故障密文足够了,可以写脚本批量调用,frida和unidbg都可
```
pip install phoenixAES
```

```python
import phoenixAES
with open('tracefile', 'wb') as t:  # 第一行是正确密文 后面是故障密文
    t.write("""1E93FA28448415F6798A4BD121259632 
1E93FA1E448426F679DE4BD1D0259632
7693FA28448415C5798AA2D1210F9632
1E937328447615F6A88A4BD121259683
1EEAFA283C8415F6798A4BD721258F32
1E93302844FF15F6598A4BD121259657
3793FA284484157E798AB9D121509632
1E936B28444D15F69F8A4BD121259666
1E07FA283F8415F6798A4BBB2125FA32
1E92FA28CF8415F6798A4B9B21256532
1E93EC28441015F6EE8A4BD1212596E4
1E93FAEA448477F6793B4BD1F2259632
1EB2FA28218415F6798A4B1B2125A432
6293FA28448415E7798A14D121419632
1E93FA32448498F679B24BD186259632
1E93FA08448491F679C94BD110259632
5993FA2844841576798AF6D121CB9632
1EB9FA28808415F6798A4B1B21259C32
8093FA28448415C4798A96D121219632
DA93FA284484155F798AE9D1213B9632
1E93FA63448491F6794E4BD134259632
1E93242844F115F67D8A4BD121259687
1E93302844B615F6508A4BD12125962B
1E93FA2F448422F679164BD199259632
1E93FAD34484F5F679D64BD16B259632
1E93FA154484FEF6796B4BD1B3259632
1E97FA28DB8415F6798A4B9621251932
1E93FAE34484EAF679484BD146259632
1E96FA284B8415F6798A4B832125C132
9793FA2844841514798A27D121CF9632
1E22FA28F48415F6798A4BC621256232
1E01FA28A28415F6798A4B3E2125E932
1EA6FA281B8415F6798A4BE321253532
1E93302844E715F6A78A4BD1212596B9
8593FA2844841578798A17D1212D9632
1E93FAB944847CF679C64BD1A5259632
1E939D2844D215F69C8A4BD121259620
1EE5FA28B48415F6798A4B7C21259F32
6093FA2844841500798ACCD1215D9632
1E93FAFF4484BEF679504BD111259632
1E37FA28ED8415F6798A4B712125F532
0693FA284484156E798A2FD121F89632
1EBCFA28078415F6798A4B6E2125C932
7493FA2844841535798AD3D121E19632
1E93A72844B915F6F98A4BD121259667
5A93FA284484151C798A09D121BB9632
BD93FA2844841560798A81D121DB9632
1EDAFA28B88415F6798A4B2621256C32
2C93FA28448415D9798A9CD121109632
1E93F728440E15F6868A4BD121259681
DE93FA2844841593798ACDD121009632
1E93FC2844F215F6298A4BD12125960D
6C93FA2844841558798AB6D121B09632
1E76FA28248415F6798A4BAF21257E32
4693FA28448415EC798A98D121D59632
1E60FA288B8415F6798A4BC021257A32
1E932528447715F66F8A4BD1212596A3
1E93B328442215F6BE8A4BD12125961A
4493FA2844841576798AACD121929632
1E93A92844BE15F6888A4BD121259649
3293FA2844841575798A69D121E19632
C993FA28448415A3798A39D121F89632
3A93FA28448415F0798AC4D121D89632
2793FA2844841550798A72D121D59632
0493FA2844841593798A53D121869632
0193FA28448415A9798A8FD121779632
1E93A128441815F66D8A4BD1212596E8
1EE7FA284F8415F6798A4BD92125E932
8393FA284484155B798AC7D121759632
0493FA28448415E6798AB8D121299632
1E931628444915F63C8A4BD121259601
1E93FA12448494F679984BD137259632
1E93C02844BC15F60A8A4BD1212596CE
1EB0FA28D58415F6798A4BF121256232
1E937C2844A715F6A28A4BD1212596E2
1E93FADD4484A5F679DA4BD13E259632
1E93FB2844FD15F6038A4BD1212596EB
1E71FA28D68415F6798A4BBD2125B832
1E93FAD94484B8F679A74BD125259632
1E93FAD544845AF679B24BD1A6259632
1E93332844AF15F6768A4BD12125966F
1E93FA024484D5F6797A4BD1F0259632
E093FA2844841540798A57D121169632
1E16FA28BE8415F6798A4B092125E832
1E933728443B15F6238A4BD1212596B1
B693FA2844841538798A12D121B99632
1EB7FA28DC8415F6798A4BA821256532
5093FA2844841563798A33D121589632
5B93FA284484158F798A37D121689632
1E93D828445F15F6CE8A4BD121259687
1E93722844EE15F6E28A4BD12125966B
1E93FA0E448435F679344BD195259632
9A93FA28448415E8798A8AD121A99632
1E935A2844D915F6648A4BD1212596B0
1E93FAE144848DF679624BD1E4259632
1E93FA31448497F679F84BD1B2259632
1E93CF28442215F6358A4BD12125965B
0493FA28448415E6798AB8D121299632
     """.encode('utf8'))
phoenixAES.crack_file('tracefile', [], True, False, 3)
# 第3个参数传False代表解密
```
![image-20241204230647639](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20241204230647639.png)

得到第10轮密钥可以利用aes_keyschedule还原出主密钥,即是最开始的密钥 [https://github.com/SideChannelMarvels/Stark](https://github.com/SideChannelMarvels/Stark)
![image-20241204230721196](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20241204230721196.png)
