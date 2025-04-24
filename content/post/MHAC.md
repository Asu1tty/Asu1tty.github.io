---
date: '2025-04-24T11:45:36+08:00'
draft: false
title: 'HMAC原理及代码实现'
tags:
  - HMAC
  - Hash
categories:
  - Crypto
---

HMAC（Hash-based Message Authentication Code，[散列](https://so.csdn.net/so/search?q=%E6%95%A3%E5%88%97&spm=1001.2101.3001.7020)消息认证码）是一种使用密码散列函数，同时结合一个加密密钥，通过特别计算方式之后产生的消息认证码（MAC）。
HMAC算法利用哈希运算，以一个密钥和一个消息为输入，生成一个消息摘要作为输出。
hmac算法通常需要以一个hash函数为载体,比如常见的有hmacMd5,hmacSha1,hmacSha256,目前在so里只见到过hmacMd5,hmacSha256,但是hmac的规则是适用所有hash函数的

HMAC算法的数学公式为：
![{\displaystyle {\textit {HMAC}}(K,m)=H{\Bigl (}(K'\oplus opad)\;||\;H{\bigl (}(K'\oplus ipad)\;||\;m{\bigr )}{\Bigr )}}](https://wikimedia.org/api/rest_v1/media/math/render/svg/fb67423fa152e335f482c2a885c9f2bbed812e81)
其中：

**H** 为密码Hash函数（如MD5或SHA-2)，能够对明文进行分组循环压缩；

**K** 为密钥（secret key）；

**m** 为要认证的消息；

**K’** 是从原始密钥 k 导出的另一个密钥（如果 k 短于散列函数的输入块大小，则向右填充零；如果比该块大小更长，则对 k 进行散列）；

**ipad** 内部填充（0x5C5C5C…5C5C，一段十六进制常量）；

**opad** 外部填充（0x363636…3636，一段十六进制常量)；

**⊕**：按位异或运算。

**||**：字符串拼接。



总结8个字就是:**两次加盐,两次hash**。

## 1. 算法实现过程
HMAC需要选择一个哈希函数作为实现的载体，这里以MD5为例
### 1.1. 第一步：扩展密钥
以字符串`admin`为例，十六进制如下
```plaintext
61 64 6D 69 6E
```

填充密钥到64字节
```plaintext
61 64 6D 69 6E 00(填充59次)
```
### 1.2. 异或0x36
将密钥逐字节异或0x36，得到**扩展密钥1**，0x36十进制是54
```plaintext
57 52 5b 5f 58 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
```
### 1.3. 异或0x54
将密钥逐字节异或0x54，得到**扩展密钥2**，0x54十进制是92
```plaintext
3d 38 31 35 32 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c
```
### 1.4. 计算，两次加盐，两次哈希
#### 1.4.1. 第一次加盐

**扩展密钥1**+**输入**,假设输入是hello,`68 65 6c 6c 6f`
```plaintext
57 52 5b 5f 58 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 68 65 6c 6c 6f
```
#### 1.4.2. 第一次哈希
上面提到，我们选择了MD5作为载体，那么对上面的数据进行一次MD5计算
```plaintext
5511e8d27f4692a69a4f6cfebbac574b
```
#### 1.4.3. 第二次加盐
**扩展密钥2**+**第一次哈希的结果**
```plaintext
3d 38 31 35 32 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 55 11 e8 d2 7f 46 92 a6 9a 4f 6c fe bb ac 57 4b
```
#### 1.4.4. 第二次哈希
对上面的输入进行一次MD5计算
```plaintext
83e029bbdf98117cafe2b973ab8a4a0f
```
![image-20250424114828841](https://raw.githubusercontent.com/Asu1tty/blog_img/main/picSource/image-20250424114828841.png)
验证成功

## 2. 代码实现
Python
```python
import hashlib
import hmac

key1 = '57525b5f583636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636'
key2 = '3d383135325c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c'

inputStr = 'hello'

str1 = bytes.fromhex(key1) + inputStr.encode() # 第一次加盐
sign1 = hashlib.md5(str1).hexdigest() # 第一次hash
print('sign1',sign1)

str2 = bytes.fromhex(key2) + bytes.fromhex(sign1) # 第二次加盐
sign2 = hashlib.md5(str2).hexdigest() # # 第二次hash
print('sign2',sign2)


sign = hmac.new('admin'.encode(), 'hello'.encode(), hashlib.md5).hexdigest()
print('sign',sign)
```
