---
date: '2025-04-23T11:48:50+08:00'
draft: false
title: 'MD5原理及代码实现'
tags:
  - MD5
  - Hash
categories:
  - Crypto
---

**MD5消息摘要算法**（英语：MD5 Message-Digest Algorithm），一种被广泛使用的[密码散列函数](https://zh.wikipedia.org/wiki/%E5%AF%86%E7%A2%BC%E9%9B%9C%E6%B9%8A%E5%87%BD%E6%95%B8 "密码散列函数")，可以产生出一个128位（16个[字节](https://zh.wikipedia.org/wiki/%E5%AD%97%E8%8A%82 "字节")）的[散列](https://zh.wikipedia.org/wiki/%E6%95%A3%E5%88%97 "散列")值（hash value），用于确保资讯传输完整一致。
将[数据](https://zh.wikipedia.org/wiki/%E6%95%B0%E6%8D%AE "数据")（如一段文字）运算变为另一固定长度值，是散列算法的基础原理。

## 1. 算法
MD5是输入不定长度，输出固定长度128-bits的算法。经过程序流程，生成四个32位数据，最后联合起来成为一个128-bits（16字节，通常消息传输中更常见表示为32 个十六进制字符）[散列](https://zh.wikipedia.org/wiki/%E6%95%A3%E5%88%97 "散列")。
## 2. 算法实现过程
### 2.1. 第一步：填充

MD5 的输入数据需要满足以下条件：

-  数据长度（以位为单位）模 512 等于 448（即模 64 字节等于 56 字节）。
-  填充后，数据长度必须是 512 位的倍数（即 64 字节的倍数）。

以字符串`admin`为例，十六进制如下
```plaintext
61 64 6D 69 6E
```
首先需要填充到64字节
第一位填充 0x80 剩下的填充 0 直到达到 56 个字节
```plaintext
61 64 6D 69 6E 80 0(填充50次) 共 56 个字节
```
接下来 8 个字节
第一位填充消息长度 * 8，也就是5 * 8 = 40 = 0x28，（0x28 & 0xFF）剩下的填充0
```plaintext
61 64 6D 69 6E 80 0(填充50次) 0x28 0(填充7次) 共 64 个字节
```

#### 2.1.1. 当输入大小恰好为56字节时
理论上，只需添加 0x80 和长度信息即可，但由于 0x80 占用 1 字节，剩余空间不足以容纳 8 字节的长度信息，因此需要填充到下一个 512 位块。

在数据末尾添加 0x80（二进制 10000000），占用 1 字节。
当前长度：56 字节 + 1 字节 = 57 字节（456 位）。
因此，填充到下一个 512 位块（128 字节 = 1024 位）
- 目标长度（不含长度信息）：128 字节 - 8 字节 = 120 字节。
- 当前长度：57 字节。
- 需要填充：120 字节 - 57 字节 = 63 字节。
- 填充 63 个 0x00 字节。
再在尾部加上消息长度信息，原始数据长度：56 × 8 = 448 位。用 64 位表示：0x000001C0（低位在前），填充为 8 字节：0xC0010000 00000000。

那么当输入大小大于56字节且小于64字节，填充方法同理

### 2.2. 第二步：分组
还是以填充后的字符串`admin`为例
需要把64字节分为16个小组，即一组4字节
```plaintext
M0: 61 64 6D 69
M1: 6E 80 0 0
M2: 0 0 0 0
............
M14: 40 0 0 0
M15: 0 0 0 0
```
### 2.3. 第三步：初始化常量
```plaintext
A=0x67452301
B=0xefcdab89
C=0x98badcfe
D=0x10325476
```
如果在内存中就会显示成小端续,01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
### 2.4. 第四步：计算

可被称为64轮运算，也可被称为四大轮，每一大轮有16小轮
在每次子循环中 FF GG HH II 函数交替使用
第一个16次使用FF
第二个16次使用GG
第三个16次使用HH
第四个16次使用II
函数定义如下
```python
def FF(a, b, c, d, x, s, ac):
	a = (a + F(b, c, d) + x + ac) & 0xFFFFFFFF
	return left_rotate(a, s) + b & 0xFFFFFFFF
def GG(a, b, c, d, x, s, ac):
	a = (a + G(b, c, d) + x + ac) & 0xFFFFFFFF
	return left_rotate(a, s) + b & 0xFFFFFFFF
def HH(a, b, c, d, x, s, ac):
	a = (a + H(b, c, d) + x + ac) & 0xFFFFFFFF
	return left_rotate(a, s) + b & 0xFFFFFFFF
def II(a, b, c, d, x, s, ac):
	a = (a + I(b, c, d) + x + ac) & 0xFFFFFFFF
	return left_rotate(a, s) + b & 0xFFFFFFFF
```

下面就是运算的核心
```python
for chunk in chunks:
    words = struct.unpack('<16I', chunk) # 将64字节数据切割16份,每份都按小端续展示. I是int的意思 对应4字节
    A, B, C, D = a0, b0, c0, d0
    # Round 1
    A = FF(A, B, C, D, words[0], 7, 0xD76AA478)
    D = FF(D, A, B, C, words[1], 12, 0xE8C7B756)
    C = FF(C, D, A, B, words[2], 17, 0x242070DB)
    B = FF(B, C, D, A, words[3], 22, 0xC1BDCEEE)
    A = FF(A, B, C, D, words[4], 7, 0xF57C0FAF)
    D = FF(D, A, B, C, words[5], 12, 0x4787C62A)
    C = FF(C, D, A, B, words[6], 17, 0xA8304613)
    B = FF(B, C, D, A, words[7], 22, 0xFD469501)
    A = FF(A, B, C, D, words[8], 7, 0x698098D8)
    D = FF(D, A, B, C, words[9], 12, 0x8B44F7AF)
    C = FF(C, D, A, B, words[10], 17, 0xFFFF5BB1)
    B = FF(B, C, D, A, words[11], 22, 0x895CD7BE)
    A = FF(A, B, C, D, words[12], 7, 0x6B901122)
    D = FF(D, A, B, C, words[13], 12, 0xFD987193)
    C = FF(C, D, A, B, words[14], 17, 0xA679438E)
    B = FF(B, C, D, A, words[15], 22, 0x49B40821)
    # Round 2
    A = GG(A, B, C, D, words[1], 5, 0xF61E2562)
    D = GG(D, A, B, C, words[6], 9, 0xC040B340)
    C = GG(C, D, A, B, words[11], 14, 0x265E5A51)
    B = GG(B, C, D, A, words[0], 20, 0xE9B6C7AA)
    A = GG(A, B, C, D, words[5], 5, 0xD62F105D)
    D = GG(D, A, B, C, words[10], 9, 0x02441453)
    C = GG(C, D, A, B, words[15], 14, 0xD8A1E681)
    B = GG(B, C, D, A, words[4], 20, 0xE7D3FBC8)
    A = GG(A, B, C, D, words[9], 5, 0x21E1CDE6)
    D = GG(D, A, B, C, words[14], 9, 0xC33707D6)
    C = GG(C, D, A, B, words[3], 14, 0xF4D50D87)
    B = GG(B, C, D, A, words[8], 20, 0x455A14ED)
    A = GG(A, B, C, D, words[13], 5, 0xA9E3E905)
    D = GG(D, A, B, C, words[2], 9, 0xFCEFA3F8)
    C = GG(C, D, A, B, words[7], 14, 0x676F02D9)
    B = GG(B, C, D, A, words[12], 20, 0x8D2A4C8A)
    # Round 3
    A = HH(A, B, C, D, words[5], 4, 0xFFFA3942)
    D = HH(D, A, B, C, words[8], 11, 0x8771F681)
    C = HH(C, D, A, B, words[11], 16, 0x6D9D6122)
    B = HH(B, C, D, A, words[14], 23, 0xFDE5380C)
    A = HH(A, B, C, D, words[1], 4, 0xA4BEEA44)
    D = HH(D, A, B, C, words[4], 11, 0x4BDECFA9)
    C = HH(C, D, A, B, words[7], 16, 0xF6BB4B60)
    B = HH(B, C, D, A, words[10], 23, 0xBEBFBC70)
    A = HH(A, B, C, D, words[13], 4, 0x289B7EC6)
    D = HH(D, A, B, C, words[0], 11, 0xEAA127FA)
    C = HH(C, D, A, B, words[3], 16, 0xD4EF3085)
    B = HH(B, C, D, A, words[6], 23, 0x04881D05)
    A = HH(A, B, C, D, words[9], 4, 0xD9D4D039)
    D = HH(D, A, B, C, words[12], 11, 0xE6DB99E5)
    C = HH(C, D, A, B, words[15], 16, 0x1FA27CF8)
    B = HH(B, C, D, A, words[2], 23, 0xC4AC5665)
    # Round 4
    A = II(A, B, C, D, words[0], 6, 0xF4292244)
    D = II(D, A, B, C, words[7], 10, 0x432AFF97)
    C = II(C, D, A, B, words[14], 15, 0xAB9423A7)
    B = II(B, C, D, A, words[5], 21, 0xFC93A039)
    A = II(A, B, C, D, words[12], 6, 0x655B59C3)
    D = II(D, A, B, C, words[3], 10, 0x8F0CCC92)
    C = II(C, D, A, B, words[10], 15, 0xFFEFF47D)
    B = II(B, C, D, A, words[1], 21, 0x85845DD1)
    A = II(A, B, C, D, words[8], 6, 0x6FA87E4F)
    D = II(D, A, B, C, words[15], 10, 0xFE2CE6E0)
    C = II(C, D, A, B, words[6], 15, 0xA3014314)
    B = II(B, C, D, A, words[13], 21, 0x4E0811A1)
    A = II(A, B, C, D, words[4], 6, 0xF7537E82)
    D = II(D, A, B, C, words[11], 10, 0xBD3AF235)
    C = II(C, D, A, B, words[2], 15, 0x2AD7D2BB)
    B = II(B, C, D, A, words[9], 21, 0xEB86D391)

    a0 = (a0 + A) & 0xFFFFFFFF
    b0 = (b0 + B) & 0xFFFFFFFF
    c0 = (c0 + C) & 0xFFFFFFFF
    d0 = (d0 + D) & 0xFFFFFFFF
```

下图为运算过程
![img](https://raw.githubusercontent.com/Asu1tty/blog_img/main/picSource/330px-MD5.png)

### 2.5. 更新结果
经过64轮计算后得到A B C D与最开始的 a0 b0 c0 d0 也就是iv相加,得到 a b c d,最后再以小端续输出结果,这就是一个分组的md5了。
当输入是两个分组时，第二个分组的初始IV为第一个分组得到的结果，也就是a b c d。更通俗的讲，第二组使用第一组的MD5结果作为向量

## 3. 代码实现
python版本
```python
import struct


def md5(message):
    def left_rotate(x, amount):
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF
    # ror   lsl | lsr

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & z) | (y & ~z)

    def H(x, y, z):
        return x ^ y ^ z

    def I(x, y, z):
        return y ^ (x | ~z)

    def FF(a, b, c, d, x, s, ac):
        a = (a + F(b, c, d) + x + ac) & 0xFFFFFFFF
        return left_rotate(a, s) + b & 0xFFFFFFFF

    def GG(a, b, c, d, x, s, ac):
        a = (a + G(b, c, d) + x + ac) & 0xFFFFFFFF
        return left_rotate(a, s) + b & 0xFFFFFFFF

    def HH(a, b, c, d, x, s, ac):
        a = (a + H(b, c, d) + x + ac) & 0xFFFFFFFF
        return left_rotate(a, s) + b & 0xFFFFFFFF

    def II(a, b, c, d, x, s, ac):
        a = (a + I(b, c, d) + x + ac) & 0xFFFFFFFF
        return left_rotate(a, s) + b & 0xFFFFFFFF

    def pad_message(message): # 填充
        original_length_bits = len(message) * 8
        message += b'\x80'
        while (len(message) + 8) % 64 != 0:
            message += b'\x00'
        message += struct.pack('<Q', original_length_bits)
        return message

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476


    message = pad_message(message)
    chunks = [message[i:i + 64] for i in range(0, len(message), 64)]
    for chunk in chunks:
        words = struct.unpack('<16I', chunk) # 将64字节数据切割16份,每份都按小端续展示. I是int的意思 对应4字节

        A, B, C, D = a0, b0, c0, d0
        # Round 1 都是 a d c b
        A = FF(A, B, C, D, words[0], 7, 0xD76AA478)
        D = FF(D, A, B, C, words[1], 12, 0xE8C7B756)
        C = FF(C, D, A, B, words[2], 17, 0x242070DB)
        B = FF(B, C, D, A, words[3], 22, 0xC1BDCEEE)
        A = FF(A, B, C, D, words[4], 7, 0xF57C0FAF)
        D = FF(D, A, B, C, words[5], 12, 0x4787C62A)
        C = FF(C, D, A, B, words[6], 17, 0xA8304613)
        B = FF(B, C, D, A, words[7], 22, 0xFD469501)
        A = FF(A, B, C, D, words[8], 7, 0x698098D8)
        D = FF(D, A, B, C, words[9], 12, 0x8B44F7AF)
        C = FF(C, D, A, B, words[10], 17, 0xFFFF5BB1)
        B = FF(B, C, D, A, words[11], 22, 0x895CD7BE)
        A = FF(A, B, C, D, words[12], 7, 0x6B901122)
        D = FF(D, A, B, C, words[13], 12, 0xFD987193)
        C = FF(C, D, A, B, words[14], 17, 0xA679438E)
        B = FF(B, C, D, A, words[15], 22, 0x49B40821)
        # Round 2
        A = GG(A, B, C, D, words[1], 5, 0xF61E2562)
        D = GG(D, A, B, C, words[6], 9, 0xC040B340)
        C = GG(C, D, A, B, words[11], 14, 0x265E5A51)
        B = GG(B, C, D, A, words[0], 20, 0xE9B6C7AA)
        A = GG(A, B, C, D, words[5], 5, 0xD62F105D)
        D = GG(D, A, B, C, words[10], 9, 0x02441453)
        C = GG(C, D, A, B, words[15], 14, 0xD8A1E681)
        B = GG(B, C, D, A, words[4], 20, 0xE7D3FBC8)
        A = GG(A, B, C, D, words[9], 5, 0x21E1CDE6)
        D = GG(D, A, B, C, words[14], 9, 0xC33707D6)
        C = GG(C, D, A, B, words[3], 14, 0xF4D50D87)
        B = GG(B, C, D, A, words[8], 20, 0x455A14ED)
        A = GG(A, B, C, D, words[13], 5, 0xA9E3E905)
        D = GG(D, A, B, C, words[2], 9, 0xFCEFA3F8)
        C = GG(C, D, A, B, words[7], 14, 0x676F02D9)
        B = GG(B, C, D, A, words[12], 20, 0x8D2A4C8A)
        # Round 3
        A = HH(A, B, C, D, words[5], 4, 0xFFFA3942)
        D = HH(D, A, B, C, words[8], 11, 0x8771F681)
        C = HH(C, D, A, B, words[11], 16, 0x6D9D6122)
        B = HH(B, C, D, A, words[14], 23, 0xFDE5380C)
        A = HH(A, B, C, D, words[1], 4, 0xA4BEEA44)
        D = HH(D, A, B, C, words[4], 11, 0x4BDECFA9)
        C = HH(C, D, A, B, words[7], 16, 0xF6BB4B60)
        B = HH(B, C, D, A, words[10], 23, 0xBEBFBC70)
        A = HH(A, B, C, D, words[13], 4, 0x289B7EC6)
        D = HH(D, A, B, C, words[0], 11, 0xEAA127FA)
        C = HH(C, D, A, B, words[3], 16, 0xD4EF3085)
        B = HH(B, C, D, A, words[6], 23, 0x04881D05)
        A = HH(A, B, C, D, words[9], 4, 0xD9D4D039)
        D = HH(D, A, B, C, words[12], 11, 0xE6DB99E5)
        C = HH(C, D, A, B, words[15], 16, 0x1FA27CF8)
        B = HH(B, C, D, A, words[2], 23, 0xC4AC5665)
        # Round 4
        A = II(A, B, C, D, words[0], 6, 0xF4292244)
        D = II(D, A, B, C, words[7], 10, 0x432AFF97)
        C = II(C, D, A, B, words[14], 15, 0xAB9423A7)
        B = II(B, C, D, A, words[5], 21, 0xFC93A039)
        A = II(A, B, C, D, words[12], 6, 0x655B59C3)
        D = II(D, A, B, C, words[3], 10, 0x8F0CCC92)
        C = II(C, D, A, B, words[10], 15, 0xFFEFF47D)
        B = II(B, C, D, A, words[1], 21, 0x85845DD1)
        A = II(A, B, C, D, words[8], 6, 0x6FA87E4F)
        D = II(D, A, B, C, words[15], 10, 0xFE2CE6E0)
        C = II(C, D, A, B, words[6], 15, 0xA3014314)
        B = II(B, C, D, A, words[13], 21, 0x4E0811A1)
        A = II(A, B, C, D, words[4], 6, 0xF7537E82)
        D = II(D, A, B, C, words[11], 10, 0xBD3AF235)
        C = II(C, D, A, B, words[2], 15, 0x2AD7D2BB)
        B = II(B, C, D, A, words[9], 21, 0xEB86D391)

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    result = struct.pack('<4I', a0, b0, c0, d0)
    return result.hex()


print(md5('admin'.encode()))
```

java版本
```java
package com.md5;

public class md5 {

    static final String[] hexs ={"0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"};
    //标准的幻数
    private static final long A=0x67452301L;
    private static final long B=0xefcdab89L;
    private static final long C=0x98badcfeL;
    private static final long D=0x10325476L;


    //下面这些S11-S44实际上是一个4*4的矩阵，在四轮循环运算中用到
    static final int S11 = 7;
    static final int S12 = 12;
    static final int S13 = 17;
    static final int S14 = 22;

    static final int S21 = 5;
    static final int S22 = 9;
    static final int S23 = 14;
    static final int S24 = 20;

    static final int S31 = 4;
    static final int S32 = 11;
    static final int S33 = 16;
    static final int S34 = 23;

    static final int S41 = 6;
    static final int S42 = 10;
    static final int S43 = 15;
    static final int S44 = 21;

    //java不支持无符号的基本数据（unsigned）
    private long [] result={A,B,C,D};//存储hash结果，共4×32=128位，初始化值为（幻数的级联）

    public static void main(String []args){
        md5 md=new md5();
        System.out.println("md5(abc)="+md.digest("admin"));
    }

    private String digest(String inputStr){
        byte [] inputBytes=inputStr.getBytes();
        int byteLen=inputBytes.length;//长度（字节）
        int groupCount=0;//完整分组的个数
        groupCount=byteLen/64;//每组512位（64字节）
        long []groups=null;//每个小组(64字节)再细分后的16个小组(4字节)

        //处理每一个完整 分组
        for(int step=0;step<groupCount;step++){
            groups=divGroup(inputBytes,step*64);
            trans(groups);//处理分组，核心算法
        }

        //处理完整分组后的尾巴
        int rest=byteLen%64;//512位分组后的余数
        byte [] tempBytes=new byte[64];
        if(rest<=56){
            for(int i=0;i<rest;i++)
                tempBytes[i]=inputBytes[byteLen-rest+i];
            if(rest<56){
                tempBytes[rest]=(byte)(1<<7);
                for(int i=1;i<56-rest;i++)
                    tempBytes[rest+i]=0;
            }
            long len=(long)(byteLen<<3);
            for(int i=0;i<8;i++){
                tempBytes[56+i]=(byte)(len&0xFFL);
                len=len>>8;
            }
            groups=divGroup(tempBytes,0);
            trans(groups);//处理分组
        }else{
            for(int i=0;i<rest;i++)
                tempBytes[i]=inputBytes[byteLen-rest+i];
            tempBytes[rest]=(byte)(1<<7);
            for(int i=rest+1;i<64;i++)
                tempBytes[i]=0;
            groups=divGroup(tempBytes,0);
            trans(groups);//处理分组

            for(int i=0;i<56;i++)
                tempBytes[i]=0;
            long len=(long)(byteLen<<3);
            for(int i=0;i<8;i++){
                tempBytes[56+i]=(byte)(len&0xFFL);
                len=len>>8;
            }
            groups=divGroup(tempBytes,0);
            trans(groups);//处理分组
        }

        //将Hash值转换成十六进制的字符串
        String resStr="";
        long temp=0;
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                temp=result[i]&0x0FL;
                String a=hexs[(int)(temp)];
                result[i]=result[i]>>4;
                temp=result[i]&0x0FL;
                resStr+=hexs[(int)(temp)]+a;
                result[i]=result[i]>>4;
            }
        }
        return resStr;
    }

    /**
     * 从inputBytes的index开始取512位，作为新的分组
     * 将每一个512位的分组再细分成16个小组，每个小组64位（8个字节）
     * @param inputBytes
     * @param index
     * @return
     */
    private static long[] divGroup(byte[] inputBytes,int index){
        long [] temp=new long[16];
        for(int i=0;i<16;i++){
            temp[i]=b2iu(inputBytes[4*i+index])|
                    (b2iu(inputBytes[4*i+1+index]))<<8|
                    (b2iu(inputBytes[4*i+2+index]))<<16|
                    (b2iu(inputBytes[4*i+3+index]))<<24;
        }
        return temp;
    }

    /**
     * 这时不存在符号位（符号位存储不再是代表正负），所以需要处理一下
     * @param b
     * @return
     */
    public static long b2iu(byte b){
        return b < 0 ? b & 0x7F + 128 : b;
    }

    private void trans(long[] groups) {
        long a = result[0], b = result[1], c = result[2], d = result[3];
        /*第一轮*/
        a = FF(a, b, c, d, groups[0], S11, 0xd76aa478L); /* 1 */
        d = FF(d, a, b, c, groups[1], S12, 0xe8c7b756L); /* 2 */
        c = FF(c, d, a, b, groups[2], S13, 0x242070dbL); /* 3 */
        b = FF(b, c, d, a, groups[3], S14, 0xc1bdceeeL); /* 4 */
        a = FF(a, b, c, d, groups[4], S11, 0xf57c0fafL); /* 5 */
        d = FF(d, a, b, c, groups[5], S12, 0x4787c62aL); /* 6 */
        c = FF(c, d, a, b, groups[6], S13, 0xa8304613L); /* 7 */
        b = FF(b, c, d, a, groups[7], S14, 0xfd469501L); /* 8 */
        a = FF(a, b, c, d, groups[8], S11, 0x698098d8L); /* 9 */
        d = FF(d, a, b, c, groups[9], S12, 0x8b44f7afL); /* 10 */
        c = FF(c, d, a, b, groups[10], S13, 0xffff5bb1L); /* 11 */
        b = FF(b, c, d, a, groups[11], S14, 0x895cd7beL); /* 12 */
        a = FF(a, b, c, d, groups[12], S11, 0x6b901122L); /* 13 */
        d = FF(d, a, b, c, groups[13], S12, 0xfd987193L); /* 14 */
        c = FF(c, d, a, b, groups[14], S13, 0xa679438eL); /* 15 */
        b = FF(b, c, d, a, groups[15], S14, 0x49b40821L); /* 16 */

        /*第二轮*/
        a = GG(a, b, c, d, groups[1], S21, 0xf61e2562L); /* 17 */
        d = GG(d, a, b, c, groups[6], S22, 0xc040b340L); /* 18 */
        c = GG(c, d, a, b, groups[11], S23, 0x265e5a51L); /* 19 */
        b = GG(b, c, d, a, groups[0], S24, 0xe9b6c7aaL); /* 20 */
        a = GG(a, b, c, d, groups[5], S21, 0xd62f105dL); /* 21 */
        d = GG(d, a, b, c, groups[10], S22, 0x2441453L); /* 22 */
        c = GG(c, d, a, b, groups[15], S23, 0xd8a1e681L); /* 23 */
        b = GG(b, c, d, a, groups[4], S24, 0xe7d3fbc8L); /* 24 */
        a = GG(a, b, c, d, groups[9], S21, 0x21e1cde6L); /* 25 */
        d = GG(d, a, b, c, groups[14], S22, 0xc33707d6L); /* 26 */
        c = GG(c, d, a, b, groups[3], S23, 0xf4d50d87L); /* 27 */
        b = GG(b, c, d, a, groups[8], S24, 0x455a14edL); /* 28 */
        a = GG(a, b, c, d, groups[13], S21, 0xa9e3e905L); /* 29 */
        d = GG(d, a, b, c, groups[2], S22, 0xfcefa3f8L); /* 30 */
        c = GG(c, d, a, b, groups[7], S23, 0x676f02d9L); /* 31 */
        b = GG(b, c, d, a, groups[12], S24, 0x8d2a4c8aL); /* 32 */

        /*第三轮*/
        a = HH(a, b, c, d, groups[5], S31, 0xfffa3942L); /* 33 */
        d = HH(d, a, b, c, groups[8], S32, 0x8771f681L); /* 34 */
        c = HH(c, d, a, b, groups[11], S33, 0x6d9d6122L); /* 35 */
        b = HH(b, c, d, a, groups[14], S34, 0xfde5380cL); /* 36 */
        a = HH(a, b, c, d, groups[1], S31, 0xa4beea44L); /* 37 */
        d = HH(d, a, b, c, groups[4], S32, 0x4bdecfa9L); /* 38 */
        c = HH(c, d, a, b, groups[7], S33, 0xf6bb4b60L); /* 39 */
        b = HH(b, c, d, a, groups[10], S34, 0xbebfbc70L); /* 40 */
        a = HH(a, b, c, d, groups[13], S31, 0x289b7ec6L); /* 41 */
        d = HH(d, a, b, c, groups[0], S32, 0xeaa127faL); /* 42 */
        c = HH(c, d, a, b, groups[3], S33, 0xd4ef3085L); /* 43 */
        b = HH(b, c, d, a, groups[6], S34, 0x4881d05L); /* 44 */
        a = HH(a, b, c, d, groups[9], S31, 0xd9d4d039L); /* 45 */
        d = HH(d, a, b, c, groups[12], S32, 0xe6db99e5L); /* 46 */
        c = HH(c, d, a, b, groups[15], S33, 0x1fa27cf8L); /* 47 */
        b = HH(b, c, d, a, groups[2], S34, 0xc4ac5665L); /* 48 */

        /*第四轮*/
        a = II(a, b, c, d, groups[0], S41, 0xf4292244L); /* 49 */
        d = II(d, a, b, c, groups[7], S42, 0x432aff97L); /* 50 */
        c = II(c, d, a, b, groups[14], S43, 0xab9423a7L); /* 51 */
        b = II(b, c, d, a, groups[5], S44, 0xfc93a039L); /* 52 */
        a = II(a, b, c, d, groups[12], S41, 0x655b59c3L); /* 53 */
        d = II(d, a, b, c, groups[3], S42, 0x8f0ccc92L); /* 54 */
        c = II(c, d, a, b, groups[10], S43, 0xffeff47dL); /* 55 */
        b = II(b, c, d, a, groups[1], S44, 0x85845dd1L); /* 56 */
        a = II(a, b, c, d, groups[8], S41, 0x6fa87e4fL); /* 57 */
        d = II(d, a, b, c, groups[15], S42, 0xfe2ce6e0L); /* 58 */
        c = II(c, d, a, b, groups[6], S43, 0xa3014314L); /* 59 */
        b = II(b, c, d, a, groups[13], S44, 0x4e0811a1L); /* 60 */
        a = II(a, b, c, d, groups[4], S41, 0xf7537e82L); /* 61 */
        d = II(d, a, b, c, groups[11], S42, 0xbd3af235L); /* 62 */
        c = II(c, d, a, b, groups[2], S43, 0x2ad7d2bbL); /* 63 */
        b = II(b, c, d, a, groups[9], S44, 0xeb86d391L); /* 64 */

        /*加入到之前计算的结果当中*/
        result[0] += a;
        result[1] += b;
        result[2] += c;
        result[3] += d;
        result[0]=result[0]&0xFFFFFFFFL;
        result[1]=result[1]&0xFFFFFFFFL;
        result[2]=result[2]&0xFFFFFFFFL;
        result[3]=result[3]&0xFFFFFFFFL;
    }

    /**
     * 下面是处理要用到的线性函数
     */
    private static long F(long x, long y, long z) {
        return (x & y) | ((~x) & z);
    }

    private static long G(long x, long y, long z) {
        return (x & z) | (y & (~z));
    }

    private static long H(long x, long y, long z) {
        return x ^ y ^ z;
    }

    private static long I(long x, long y, long z) {
        return y ^ (x | (~z));
    }

    private static long FF(long a, long b, long c, long d, long x, long s,
                           long ac) {
        a += (F(b, c, d)&0xFFFFFFFFL) + x + ac;
        a = ((a&0xFFFFFFFFL)<< s) | ((a&0xFFFFFFFFL) >>> (32 - s));
        a += b;
        return (a&0xFFFFFFFFL);
    }

    private static long GG(long a, long b, long c, long d, long x, long s,
                           long ac) {
        a += (G(b, c, d)&0xFFFFFFFFL) + x + ac;
        a = ((a&0xFFFFFFFFL) << s) | ((a&0xFFFFFFFFL) >>> (32 - s));
        a += b;
        return (a&0xFFFFFFFFL);
    }

    private static long HH(long a, long b, long c, long d, long x, long s,
                           long ac) {
        a += (H(b, c, d)&0xFFFFFFFFL) + x + ac;
        a = ((a&0xFFFFFFFFL) << s) | ((a&0xFFFFFFFFL) >>> (32 - s));
        a += b;
        return (a&0xFFFFFFFFL);
    }

    private static long II(long a, long b, long c, long d, long x, long s,
                           long ac) {
        a += (I(b, c, d)&0xFFFFFFFFL) + x + ac;
        a = ((a&0xFFFFFFFFL) << s) | ((a&0xFFFFFFFFL) >>> (32 - s));
        a += b;
        return (a&0xFFFFFFFFL);
    }
}
```
