---
date: '2025-04-23T13:28:36+08:00'
draft: false
title: 'SHA-1原理及代码实现'
tags:
  - SHA-1
  - Hash算法
categories:
  - Crypto
---

**SHA-1**（英語：Secure Hash Algorithm 1，中文名：安全散列算法1）是一种[密码散列函数](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A0%81%E6%95%A3%E5%88%97%E5%87%BD%E6%95%B0 "密码散列函数")，[美国国家安全局](https://zh.wikipedia.org/wiki/%E7%BE%8E%E5%9B%BD%E5%9B%BD%E5%AE%B6%E5%AE%89%E5%85%A8%E5%B1%80 "美国国家安全局")设计。SHA-1可以生成一个被称为消息摘要的160[位](https://zh.wikipedia.org/wiki/%E4%BD%8D "位")（20[字节](https://zh.wikipedia.org/wiki/%E5%AD%97%E8%8A%82 "字节")）散列值，散列值通常的呈现形式为40个[十六进制](https://zh.wikipedia.org/wiki/%E5%8D%81%E5%85%AD%E8%BF%9B%E5%88%B6 "十六进制")数。
## 1. 算法实现过程
### 1.1. 第一步：填充
以字符串`admin`为例，十六进制如下
```plaintext
61 64 6D 69 6E
```
需要让它填充到64个字节长度

第一位填充 0x80 剩下的填充 0 直到达到 56 个字节
```plaintext
61 64 6D 69 6E 80 0(填充50次) 共 56 个字节
```
接下来 8 个字节
消息长度 * 8，也就是5 * 8 = 40 = 0x28
```plaintext
61 64 6D 69 6E 80 0(填充50次) 0(填充7次) 0x28 共 64 个字节
```
填充这块唯一和md5有区别的就是,最后的附加消息长度是大端续,也就是正常的顺序
64字节的分组长度,md5,sha1,sha256都是, sha512是128字节分组。
### 1.2. 第二步：扩充
sha1有80轮循环,每一轮要用不同的数据,而填充后的最多只有16个4字节数据,所以需要进行扩展

前16个四字节复制填充后的16个四字节
后64个四字节使用扩充算法进行扩充
当前位置值 =（ 前面第3个四字节 ^ 前面第8个四字节 ^ 前面第14个四字节 ^ 前面第16个四字节 ）<< 1

<< 代表循环左移
用代码表示
```python
# 扩展到80个字
for j in range(16, 80):
    w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)
```
以字符串admin为例，扩充如下
```plaintext
0x61646D69 0x6E800000 0x00000000 0x00000000
0x00000000 0x00000000 0x00000000 0x00000000
0x00000000 0x00000000 0x00000000 0x00000000
0x00000000 0x00000000 0x00000000 0x00000028
0xC2C8DAD2 0xDD000000 0x00000050 0x8591B5A5
0xBA000001 0x000000A0 0x0B236B4B 0x74000053
0x8591B4E5 0xAC46D697 0xE8000006 0x00000280
0x2C8DAD2C 0xD000011D 0x93D76633 0x0B1B5AAF
0x2EB2DEF5 0xCE000A02 0xB236B5F0 0x5646D2E1
0xA75D98C8 0x2C6D683C 0x9646D6F8 0xE8002946
0xDE9C0454 0xE80011DB 0x3D766339 0xB1B5AA50
0xE00E8419 0x9400A16F 0x352D88DD 0x9A2BFBE5
0xAC319C7D 0x8AD683CA 0x646D6BC9 0xCF5F19E0
0xB78693C6 0x680117B8 0x65508723 0x5B5AA17C
0x4FB5D950 0x6C677EC5 0xC49E5B2B 0x4ABF971F
0x1D85C38E 0x45682C33 0x6DE60939 0xAC4435BA
0x850205AF 0x8811DBAC 0x76632D3D 0xD1C739D0
0x8E84198E 0x00A16F94 0x2D88DD35 0x2BFBE71A
0x1D11D080 0x0683DE87 0x0906A505 0x8602A4F9
0xF0C81B7D 0xC117A631 0x86DCEAB4 0xFECC24E3
```
### 1.3. 第三步：初始化常量
```plaintext
h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0
```
前4个iv是和md5一样的,最后一个0xC3D2E1F0只有sha1才有,如果出现了这个98%是有sha1运算的。
### 1.4. 第四步：计算
首先重新定义五个变量
a=A，b=B，c=C，d=D，e=E
```python
for j in range(80):
    if 0 <= j <= 19:
        f = (b & c) | (~b & d)
        k = 0x5A827999
    elif 20 <= j <= 39:
        f = b ^ c ^ d
        k = 0x6ED9EBA1
    elif 40 <= j <= 59:
        f = (b & c) | (b & d) | (c & d)
        k = 0x8F1BBCDC
    elif 60 <= j <= 79:
        f = b ^ c ^ d
        k = 0xCA62C1D
    temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
    e = d
    d = c
    c = left_rotate(b, 30)
    b = a
    a = temp
```

其中K表可以作为逆向分析中的特征
```python
k0 = 0x5A827999 //0 <= i <= 19
k1 = 0x6ED9EBA1 //20 <= i <= 39
k2 = 0x8F1BBCDC //40 <= i <= 59
k3 = 0xCA62C1D6 //60 <= i <= 79
```
### 1.5. 更新结果
运算完成后，abcde获得了更新，然后相加赋值给ABCDE
```plaintext
A = (A + a) & 0xFFFFFFFFL
B = (B + b) & 0xFFFFFFFFL
C = (C + c) & 0xFFFFFFFFL
D = (D + d) & 0xFFFFFFFFL
E = (E + e) & 0xFFFFFFFFL
```

## 2. 代码实现
Python代码实现
```python
def sha1(data):
    def left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF
    # 初始化哈希值
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # 预处理
    original_byte_len = len(data)
    original_bit_len = original_byte_len * 8
    data += b'\x80'

    while (len(data) + 8) % 64 != 0:
        data += b'\x00'

    data += original_bit_len.to_bytes(8, 'big')  # 附加消息长度 大端序

    # 处理每个512-bit块
    for i in range(0, len(data), 64):
        w = [0] * 80
        chunk = data[i:i + 64]
        # 将块划分为16个32-bit字
        for j in range(16):
            w[j] = int.from_bytes(chunk[4 * j:4 * j + 4], 'big')

        # 扩展到80个字
        for j in range(16, 80):
            w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # 初始化hash值
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # 主循环
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
    return ''.join(f'{x:08x}' for x in [h0, h1, h2, h3, h4])

message = "admin"
data = message.encode()
hash_value = sha1(data)
print(hash_value)
```

Java代码实现
```Java
package com.sha1;


import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Created by YotWei on 2017/10/28.
 * sha1
 */
public class SHA1Demo {

    public static void main(String[] args) throws Exception {

        String s = "admin";
        System.out.println(s);
        System.out.println("sha1: " + SHA1.generate(s.getBytes()));
    }
}
 
class SHA1 {
    static String generate(byte[] dataBytes) throws Exception {

        byte[] fillBytes = new byte[64 * ((dataBytes.length + 8) / 64 + 1)];
        int i;
        for (i = 0; i < dataBytes.length; i++) {
            fillBytes[i] = dataBytes[i];
        }

        //fill 100000.....00
        fillBytes[i] = (byte) 0x80;

        //fill length
        long len = dataBytes.length * 8L;
        for (int j = fillBytes.length - 8, k = 0; j < fillBytes.length; j++, k++) {
            fillBytes[j] = (byte) (len >> ((7 - k) * 8));
        }
        //cast bytes to ints
        int[] bytes2Ints = byteArrToIntArr(fillBytes);

        int[] k = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
        int[] h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

        for (int j = 0; j < bytes2Ints.length; j += 16) {
            int[] w = new int[80];
            System.arraycopy(bytes2Ints, j, w, 0, 16);

            int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

            for (int t = 0; t < 80; t++) {
                if (t >= 16) {
                    w[t] = s(1, w[t - 16] ^ w[t - 14] ^ w[t - 8] ^ w[t - 3]);
                }
                int temp = s(5, a) + f(t, b, c, d) + e + w[t] + k[t / 20];
                e = d;
                d = c;
                c = s(30, b);
                b = a;
                a = temp;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
        }
        return String.format("%08x%08x%08x%08x%08x", h[0], h[1], h[2], h[3], h[4]);
    }

    private static int f(int t, int b, int c, int d) {
        switch (t / 20) {
            case 0:
                return (b & c) | (~b & d);
            case 2:
                return (b & c) | (b & d) | (c & d);
            default:
                return b ^ c ^ d;
        }
    }

    private static int s(int lmov, int num) {
        return num << lmov | num >>> (32 - lmov);
    }

    private static int[] byteArrToIntArr(byte[] bytes) throws Exception {
        if (bytes.length % 4 != 0) {
            throw new Exception("Parse Error");
        }
        int[] intArr = new int[bytes.length / 4];
        for (int i = 0; i < intArr.length; i++) {
            intArr[i] = bytes[i * 4 + 3] & 0x000000ff |
                    bytes[i * 4 + 2] << 8 & 0x0000ff00 |
                    bytes[i * 4 + 1] << 16 & 0x00ff0000 |
                    bytes[i * 4] << 24 & 0xff000000;
        }
        return intArr;
    }
}
```
