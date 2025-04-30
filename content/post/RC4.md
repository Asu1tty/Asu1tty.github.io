---
date: '2025-04-25T17:21:36+08:00'
draft: false
title: 'RC4原理及代码实现'
tags:
  - RC4
  - 流密码
categories:
  - Crypto
---

在[密码学](https://en.wikipedia.org/wiki/Cryptography "Cryptography")中，**RC4**（Rivest Cipher 4，也称为 **ARC4** 或 **ARCFOUR，** 意思是Alleged（所谓的） RC4）是一种[流密码](https://en.wikipedia.org/wiki/Stream_cipher "Stream cipher") 。虽然它在软件中以其简单性和速度而著称，但在 RC4 中发现了多个漏洞，使其不安全。
流密码（streamcipher）是对数据流进行连续处理的一类密码算法。流密码中一般以1比特、8比特或32比特等为单位进行加密和解密。其中RC4的加解密单位为8比特，也就是一个字节。


## 1. 密码学中为什么经常使用异或？
在密码学中经常使用异或运算，`RC4`的原理也依赖异或运算。
下面解释摘自《图解密码技术 第三版》

`由于两个相同的数进行XOR运算的结果一定为0，因此如果将A⊕B的结果再与B进行XOR运算，则结果会变回A。也就是说，两个公式中的B会相互抵消。`
- 将明文A用密钥B进行加密，得到密文A⊕B
- 将密文A⊕B用密钥B进行解密，得到明文A
![image-20250425172319106](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425172319106.png)
图片摘自《图解密码技术 第三版》

`从图中可以看出，执行一次蒙版操作后，原来的图像被隐藏（掩盖）了，而执行两次蒙版操作后，就又可以得到原来的图像了。`
`如果所使用的蒙版是完全随机的比特序列，则使用XOR就可以将原来的图像掩盖起来。但如果蒙版中的比特序列的排列是可以被推测出来的，那么实质上图像就没有被真正掩盖。对于密码技术来说，“是否可以预测”是非常重要的一点。能够产生不可预测的比特序列，对于密码技术的贡献是巨大的。这种不可预测的比特序列就称为随机数。`


## 2. 算法实现过程

### 2.1. KSA(key-scheduling algorithm)
使用密钥调度算法(key-scheduling algorithm)
- **输入**：一个可变长度的密钥（通常8-2048位）。
- **输出**：一个256字节的置换数组S（S[0]到S[255]）。
#### 2.1.1. 第一步
先初始化256字节的数组S，填充0到255的整数，即S[0]=0, S[1]=1, ..., S[255]=255。

#### 2.1.2. 第二步
创建一个临时数组T，长度与密钥相同，将密钥循环填充到T中（如果密钥长度不足256字节，则重复密钥）。

#### 2.1.3. 第三步
使用以下伪代码进行置换
```pseudo
for i = 0 to 255
    j = (j + S[i] + T[i]) mod 256
    swap S[i] and S[j]
```
S数组被打乱，形成一个基于密钥的伪随机置换表。这样处理之后，就得到了介绍中提到的`不可预测的比特序列`
### 2.2. PRGA(pseudo-random generation algorithm)
使用伪随机生成算法生成比特流。
- **输入**：初始化后的S数组，待加密/解密的明文/密文。
- **输出**：与明文/密文等长的密钥流（keystream）。
初始化两个变量i和j为0，执行以下伪代码
```pseudo
i = (i + 1) mod 256
j = (j + S[i]) mod 256
swap S[i] and S[j]
t = (S[i] + S[j]) mod 256
output S[t]
```
生成与输入明文/密文等长的密钥流。
## 3. 密文与明文关系
根据前面的介绍可以得到如下关系

- 将生成的密钥流与明文逐字节进行`异或(XOR)`操作，得到密文：
```text
密文[i] = 明文[i] XOR 密钥流[i]
```
- 解密过程相同，因为XOR是可逆的：
```text
明文[i] = 密文[i] XOR 密钥流[i]
```

## 4. 代码实现
Python
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author: @manojpandey

# Python 3 implementation for RC4 algorithm
# Brief: https://en.wikipedia.org/wiki/RC4

# Will use codecs, as 'str' object in Python 3 doesn't have any attribute 'decode'
import codecs

MOD = 256


def KSA(key):
    ''' Key Scheduling Algorithm (from wikipedia):
        for i from 0 to 255
            S[i] := i
        endfor
        j := 0
        for i from 0 to 255
            j := (j + S[i] + key[i mod keylength]) mod 256
            swap values of S[i] and S[j]
        endfor
    '''
    key_length = len(key)
    # create the array "S"
    S = list(range(MOD))  # [0,1,2, ... , 255]
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]  # swap values

    return S


def PRGA(S):
    ''' Psudo Random Generation Algorithm (from wikipedia):
        i := 0
        j := 0
        while GeneratingOutput:
            i := (i + 1) mod 256
            j := (j + S[i]) mod 256
            swap values of S[i] and S[j]
            K := S[(S[i] + S[j]) mod 256]
            output K
        endwhile
    '''
    i = 0
    j = 0
    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD

        S[i], S[j] = S[j], S[i]  # swap values
        K = S[(S[i] + S[j]) % MOD]
        yield K


def get_keystream(key):
    ''' Takes the encryption key to get the keystream using PRGA
        return object is a generator
    '''
    S = KSA(key)
    return PRGA(S)


def encrypt_logic(key, text):
    ''' :key -> encryption key used for encrypting, as hex string
        :text -> array of unicode values/ byte string to encrpyt/decrypt
    '''
    # For plaintext key, use this
    key = [ord(c) for c in key]
    # If key is in hex:
    # key = codecs.decode(key, 'hex_codec')
    # key = [c for c in key]
    keystream = get_keystream(key)

    res = []
    for c in text:
        val = ("%02X" % (c ^ next(keystream)))  # XOR and taking hex
        res.append(val)
    return ''.join(res)


def encrypt(key, plaintext):
    ''' :key -> encryption key used for encrypting, as hex string
        :plaintext -> plaintext string to encrpyt
    '''
    plaintext = [ord(c) for c in plaintext]
    return encrypt_logic(key, plaintext)


def decrypt(key, ciphertext):
    ''' :key -> encryption key used for encrypting, as hex string
        :ciphertext -> hex encoded ciphered text using RC4
    '''
    ciphertext = codecs.decode(ciphertext, 'hex_codec')
    res = encrypt_logic(key, ciphertext)
    return codecs.decode(res, 'hex_codec').decode('utf-8')


def main():

    key = 'not-so-random-key'  # plaintext
    plaintext = 'Good work! Your implementation is correct'  # plaintext
    # encrypt the plaintext, using key and RC4 algorithm
    ciphertext = encrypt(key, plaintext)
    print('plaintext:', plaintext)
    print('ciphertext:', ciphertext)
    # ..
    # Let's check the implementation
    # ..
    ciphertext = '2D7FEE79FFCE80B7DDB7BDA5A7F878CE298615'\
        '476F86F3B890FD4746BE2D8F741395F884B4A35CE979'
    # change ciphertext to string again
    decrypted = decrypt(key, ciphertext)
    print('decrypted:', decrypted)

    if plaintext == decrypted:
        print('\nCongrats ! You made it.')
    else:
        print('Shit! You pooped your pants ! .-.')

    # until next time folks !


def test():

    # Test case 1
    # key = '4B6579' # 'Key' in hex
    # key = 'Key'
    # plaintext = 'Plaintext'
    # ciphertext = 'BBF316E8D940AF0AD3'
    assert(encrypt('Key', 'Plaintext')) == 'BBF316E8D940AF0AD3'
    assert(decrypt('Key', 'BBF316E8D940AF0AD3')) == 'Plaintext'

    # Test case 2
    # key = 'Wiki' # '57696b69'in hex
    # plaintext = 'pedia'
    # ciphertext should be 1021BF0420
    assert(encrypt('Wiki', 'pedia')) == '1021BF0420'
    assert(decrypt('Wiki', '1021BF0420')) == 'pedia'

    # Test case 3
    # key = 'Secret' # '536563726574' in hex
    # plaintext = 'Attack at dawn'
    # ciphertext should be 45A01F645FC35B383552544B9BF5
    assert(encrypt('Secret',
                   'Attack at dawn')) == '45A01F645FC35B383552544B9BF5'
    assert(decrypt('Secret',
                   '45A01F645FC35B383552544B9BF5')) == 'Attack at dawn'

if __name__ == '__main__':
    main()
```
