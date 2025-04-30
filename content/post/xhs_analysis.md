---
date: '2025-04-25T17:48:36+08:00'
draft: false
title: '某红薯shield参数分析'
tags:
  - app reverse
categories:
  - 逆向实战
---



版本：8.70.0

## 1. 加密入口

加密入口在`com.xingin.shield.http.XhsHttpInterceptor`

jadx打开发现有如下Native层函数，intercept为拦截器，hook拦截器，并且打印`chain.request()`中的参数会发现传入前没有`shield`参数，执行完后有`shield`参数，正是在此Native层拦截器完成加密，并且通过函数名称也能猜测到so层有初始化操作

![image-20250425175501568](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425175501568.png)

![image-20250425175516047](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425175516047.png)

![image-20250425175533360](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425175533360.png)

在jadx反编译中并没有看到加载so的字样，所以通过hook`registerNatives`查找动态注册地址

![image-20250425180205084](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425180205084.png)



## 确认初始化操作

对上面三个Native层函数进行hook

![image-20250425180700015](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425180700015.png)

可以发现：

- 首先调用`initializeNative`
- 然后调用`initialize`,传入字符串`main`，得到long类型返回值
- 后面的拦截器都传入了初始化后得到的long类型返回值

## 上Unidbg

unidbg补环境模板

```java
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import com.github.unidbg.virtualmodule.android.MediaNdkModule;
import com.github.unidbg.virtualmodule.android.SystemProperties;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class tmp extends AbstractJni implements IOResolver {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
	    System.out.println("==================open file=========================");
        System.out.println("open file:" + pathname);
        return null;
    }


    tmp(){
        // 创建模拟器实例
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.xxx").addBackendFactory(new Unicorn2Factory(false)).build();
        // 添加IO接口要加这句
        emulator.getSyscallHandler().addIOResolver(this);
        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机,传入APK，Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/java/com//files/.apk"));
        // 4个虚拟模块
        new AndroidModule(emulator,vm).register(memory); //libandroid.so
        new MediaNdkModule(emulator,vm).register(memory); // libmediandk.so
        new JniGraphics(emulator,vm).register(memory); // libjnigraphics.so
        new SystemProperties(emulator,null).register(memory); // libsystemproperties.so
        // 设置JNI
        vm.setJni(this);
        // 打印日志
        vm.setVerbose(true);
        // 加载目标SO
        DalvikModule dm = vm.loadLibrary("soname", true);
        // DalvikModule dm = vm.loadLibrary(new File("unidbg-android/apks/xx/lib.so"), true);
        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        // 调用JNI OnLoad
        dm.callJNI_OnLoad(emulator);
    };
    public void callByAddress(){
        // args list
        List<Object> list = new ArrayList<>(10);
        // jnienv
        list.add(vm.getJNIEnv());
        // jclazz
        list.add(0);
        // str1
        list.add(vm.addLocalObject(new StringObject(vm, "str1")));



        // strArr 假设字符串包含两个字符串
        // str6_1
        StringObject str6_1 = new StringObject(vm, "str6_1");
        vm.addLocalObject(str6_1);
        // str6_2
        StringObject str6_2 = new StringObject(vm, "str6_2");
        vm.addLocalObject(str6_2);

        ArrayObject arrayObject = new ArrayObject(str6_1,str6_2);
        list.add(vm.addLocalObject(arrayObject));

        // 最后的int
        list.add(1);

        Number number = module.callFunction(emulator, 0x2301, list.toArray());
        ArrayObject resultArr = vm.getObject(number.intValue());
        System.out.println("result:"+resultArr);
    };

    public void callByAPI(){
        DvmClass RequestCryptUtils = vm.resolveClass("com/meituan/android/payguard/RequestCryptUtils");

        StringObject str6_1 = new StringObject(vm, "str6_1");
        vm.addLocalObject(str6_1);
        StringObject str6_2 = new StringObject(vm, "str6_2");
        vm.addLocalObject(str6_2);
        ArrayObject arrayObject = new ArrayObject(str6_1,str6_2);

        ArrayObject result = RequestCryptUtils.callStaticJniMethodObject(emulator, "encryptRequestWithRandom()", "str1","str2", "str3","str4","str5",arrayObject,1);
        System.out.println(result);
    };
    public void trace(){
    String traceFile = "unidbg-android/src/test/java/com/xx/trace.txt";
    PrintStream traceStream = null;
    try{
        traceStream = new PrintStream(new FileOutputStream(traceFile), true);
    } catch (FileNotFoundException e) {
        e.printStackTrace();
    }
    //核心 trace 开启代码，也可以自己指定函数地址和偏移量
	    emulator.traceCode(module.base,module.base+module.size).setRedirect(traceStream);
	}

	public void HookByConsoleDebugger(){
        Debugger debugger = emulator.attach();
//        debugger.addBreakPoint(module.base + 0x15610);

//        emulator.traceWrite(0x40420bc0, 0x40420bc0+32);

        debugger.addBreakPoint(module.findSymbolByName("memcpy").getAddress(), new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                int len = context.getIntArg(2);
                UnidbgPointer pointer1 = context.getPointerArg(0);
                UnidbgPointer pointer2 = context.getPointerArg(1);
                Inspector.inspect(pointer2.getByteArray(0,len),"dest "+Long.toHexString(pointer1.peer)+" src "+Long.toHexString(pointer2.peer));
                return true;
            }
        });

    }


    public static void main(String[] args) {
        tmp demo = new tmp();
        //demo.callByAddress();
        //demo.callByAPI();
    }
}
```

修改包名，填写apk地址，填写so名称后，开始运行

## 补环境

出现第一个环境错误

`com/xingin/shield/http/ContextHolder->sLogger:Lcom/xingin/shield/http/ShieldLogger;`

![image-20250425181625443](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425181625443.png)

补上

![image-20250425181810806](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425181810806.png)

再次运行，JNI_Onload返回正常。

### 第一个初始化



![image-20250425191507576](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425191507576.png)

运行报错，补环境

![image-20250425191602776](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425191602776.png)

```java
case "com/xingin/shield/http/ShieldLogger->nativeInitializeStart()V": {
    return;
}
```



继续补

![image-20250425191806115](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425191806115.png)

```java
case "java/nio/charset/Charset->defaultCharset()Ljava/nio/charset/Charset;":{
    return dvmClass.newObject(Charset.defaultCharset());
}
```



继续补

![image-20250425192257786](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425192257786.png)

通过名称可以看到是在取deviceid，把真机的拿过来就行了

![image-20250425192239711](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425192239711.png)

```java
case "com/xingin/shield/http/ContextHolder->sDeviceId:Ljava/lang/String;": {
    return new StringObject(vm,"b2e8e75b-d18d-35dc-87c3-490cf0bb7f30");
}
```

继续补，刚才的appid也拿出来

![image-20250425192523305](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425192523305.png)

```java
case "com/xingin/shield/http/ContextHolder->sAppId:I": {
    return -319115519;
}
```

继续补

![image-20250425192716192](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425192716192.png)

```java
case "com/xingin/shield/http/ShieldLogger->nativeInitializeEnd()V": {
    return;
}
```

到此第一个初始化完成

### 第二个初始化

![image-20250425193000047](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425193000047.png)

继续补环境

![image-20250425193147241](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425193147241.png)

```java
case "com/xingin/shield/http/ShieldLogger->initializeStart()V": {
    return;
}
```

继续补环境，下面这是经典的补环境问题，建议看龙哥这篇文章[SO逆向入门实战教程八：文件读写](https://blog.csdn.net/qq_38851536/article/details/118024298)

![image-20250425193300633](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425193300633.png)

直接给出代码

```java
case "android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;": {
    return vm.resolveClass("android/content/SharedPreferences").newObject(vaList.getObjectArg(0).getValue().toString());
}
```

继续补，跟上面问题是同一个

![image-20250425193750515](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425193750515.png)

```java
case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;": {
    String fileName = dvmObject.getValue().toString();
    switch (fileName) {
        case "s":{
            String key = vaList.getObjectArg(0).getValue().toString();
            System.out.println("key:"+key);
            switch (key) {
                case "main":{
                    return new StringObject(vm,"");
                }
                case "main_hmac":{
                    return new StringObject(vm,"u4IlKqm1pHQ/Y6YVkZRNG5+q2KYrjnQUdALX9aN8qWiLP2w8IjCtWoEB35lsCqqOURXQLZ4dPf+HjtuNs/RNUX2KaMHwxCfJN+HTOgUWmdEbbqYn42qyGX/Qw0b19LAo");
                }
            }
        }
    }
}
```

继续补

![image-20250425194029295](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250425194029295.png)

```java
case "com/xingin/shield/http/Base64Helper->decode(Ljava/lang/String;)[B":{
    String input = vaList.getObjectArg(0).getValue().toString();
    return new ByteArray(vm, Base64.decodeBase64(input));
}
```



## trace

首先trace一份代码，放在一边。

## 分析算法

### base64

在日志中搜索结果，找到第一次出现的位置

![image-20250427133326861](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427133326861.png)

IDA中跳转过去看看

别忘记是NewStringUTF函数生成字符串，所以参数`a1`很有可能是`JNIEnv`,重命名一下

![image-20250427134801541](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427134801541.png)

看一下这一行的汇编

![image-20250427134910915](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427134910915.png)

`x1`就应该是第一个参数，下断点看一下

```java
Debugger debugger = emulator.attach();
debugger.addBreakPoint(module.base + 0xBCF2C);
```

![image-20250427135157251](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427135157251.png)

直接监控谁往地址`0x40461018`写入，一共134字节

```java
emulator.traceWrite(0x40461018, 0x40461018+134);
```

![image-20250427135424123](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427135424123.png)

![image-20250427135513290](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427135513290.png)

前两个字节 `58 59`是固定的，所以看后面的写入,到`0x9f0f0`看看

![image-20250427135811260](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427135811260.png)

上一行是`memcpy`，下断点看看源数据地址

```java
Debugger debugger = emulator.attach();
debugger.addBreakPoint(module.base + 0x9F0EC);
```

![image-20250427140038478](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427140038478.png)

追踪地址`0x4059a018`写入

![image-20250427140221103](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427140221103.png)

跳转到`0x4bfac`看一下

![image-20250427140628796](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427140628796.png)

点进`byte_c0244`看一下

![image-20250427140700979](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427140700979.png)

如果熟悉会发现这个base64的ASCII码表

不熟悉也没事，将整个`sub_4BF44`函数丢给AI，让AI分析

![image-20250427140851887](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427140851887.png)

现在的关键就是要验证这是不是标准的base64

在`4BF44`下断点，看看入参

![image-20250427141112488](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427141112488.png)

对比发现是标准的base64

![image-20250427141138180](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427141138180.png)

那么需要追踪的数据就变成了

![image-20250427141244694](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427141244694.png)

那么继续追踪地址`0x40456098`的写入

![image-20250427141610108](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427141610108.png)

![image-20250427141630804](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427141630804.png)

![image-20250427141819502](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427141819502.png)



继续追踪`0x40593000`的写入

![image-20250427141854821](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427141854821.png)

![image-20250427142152023](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427142152023.png)



可以发现，前16个字节是在不同的地址写入的，先看前16字节,`0x4972c`

![image-20250427142340223](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427142340223.png)

`v4`来自于第一个入参，看看入参

![image-20250427142534193](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427142534193.png)

是指针，看看这个地址,注意内存中小端序`0x404531f0`

![image-20250427142729386](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427142729386.png)

那么继续跟踪`0x404531f5`偏移16字节的写入

![image-20250427143340084](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427143340084.png)

跳转过去可以看到

![image-20250427143443778](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427143443778.png)

前两个`00000001`都是在so里面固定的

`a1`是入参第一个，看看入参

```java
Debugger debugger = emulator.attach();
debugger.addBreakPoint(module.base + 0x4926C);
```

![image-20250427143859160](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427143859160.png)

是一个地址，看看这个地址`0x4058e010`

![image-20250427143937058](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427143937058.png)

那么根据这个地址的数据以及

`n0x18 = (*(*a1 + 20LL) + *(*a1 + 24LL) + *(*a1 + 28LL) + 24);`可以得到

`0x07+0x24+0x10+24 = 0x53`

那么继续看看这`0x07+0x24+0x10`三个数据是怎么来

```java
emulator.traceWrite(0x4058e024, 0x4058e024+9);
```

分别来自

![image-20250427144941488](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427144941488.png)

![image-20250427144951754](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427144951754.png)

![image-20250427145009772](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427145009772.png)



![image-20250427144841923](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427144841923.png)分别来自`a2`，`a5`，`n`，来自函数`4908C`的第二个，第五个，第七个参数

下断点看看参数

```java
Debugger debugger = emulator.attach();
debugger.addBreakPoint(module.base + 0x4908C);
```

![image-20250427145322541](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427145322541.png)

是个地址，看看`0x40459038`

![image-20250427145354404](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427145354404.png)

此时就会发现这个数组是传入的`appVersionCode`

长度是0x07

![image-20250427145550310](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427145550310.png)

又是一个地址，看看`0x4045a018`

![image-20250427145614323](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427145614323.png)

是`deviceId`，长度0x24

![image-20250427151444701](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427151444701.png)

长度0x10，是后面魔改md5的结果

前16字节到此分析结束，其实通过前面的抓包对比，心里就要有预期，前面可能是固定的

### 后面的0x53字节

### RC4



![image-20250427151725341](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427151725341.png)

追踪地址`0x4045e060`

```java
emulator.traceWrite(0x4045e060, 0x4045e060+0x53);
```

![image-20250427151852633](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427151852633.png)

跳转过去看看`0x5126c`

代码里面出现许多置换操作和异或操作，很可能是RC4，通过将伪代码丢给AI，也可以分析得到

![image-20250427152410958](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427152410958.png)

那么看看入参

```java
Debugger debugger = emulator.attach();
debugger.addBreakPoint(module.base + 0x511E0);
```



![image-20250427152613283](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427152613283.png)

x1寄存器的0x53不正好是我们数据的长度吗？

![image-20250427152726030](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427152726030.png)

第一个参数就是RC4算法的S盒

在结果处下断点

![image-20250427153437764](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427153437764.png)

查看入参显示的地址`0x4045e060`
![image-20250427153520879](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427153520879.png)

正好是我们想要的结果

那么需要验证是否是我们想要的标准RC4算法，那么先找到入参

![image-20250427153810159](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427153810159.png)

我们还知道RC4算法的S盒生成需要密钥，所以我们需要找到这个密钥

看看是谁调用了函数`sub_511E0`

可以看到有两个调用，这个时候使用trace的代码可以轻松的判断只走了第一个

![image-20250427154039388](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427154039388.png)

跳过去看看

![image-20250427154119183](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427154119183.png)

我们知道第一个参数，也就是`v21`是S盒，那么S盒很有可能在`sub_51698`中生成

丢给AI也可以很容易的分析到，这就是RC4的密钥调度算法，用于初始化RC4的S盒。

![image-20250427154442513](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427154442513.png)

那么我们只需要得到这个函数的第三个参数就行了

![image-20250427154626631](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427154626631.png)

其实细心的朋友可以发现，IDA早就帮我们把密钥显示出来了，密钥就是字符`std::abort();`

那么验证一下

![image-20250427154922588](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427154922588.png)

验证成功，那么需要追踪的数据就变成了

![image-20250427155015789](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427155015789.png)

可以先分析这段数据的组成

`00 00 00 01 + app_id + 00 00 00 02 00 00 00 07 00 00 00 24 00 00 00 10 + build + deviceId + 18 D2 64 FD 56 08 DB 27 20 90 1F F0 65 A4 BF 27`





看看unidbg日志中有没有这段数据的记录

![image-20250427155105590](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427155105590.png)

其中`00 00 00 01`固定，`00 00 00 02 00 00 00 07 00 00 00 24 00 00 00 10`是之前分析前16字节的数据

那么只剩下最后的16字节未知，16字节的数据，那么很有可能与哈希算法中的md5有关。

### 魔改HMAC MD5

在unidbg控制台搜索一下

![image-20250427163809176](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427163809176.png)

追踪一下地址`0xbffff478`,16个字节

```java
emulator.traceWrite(0xbffff478L, 0xbffff478+16);
```

![image-20250427164147693](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427164147693.png)

跳转过去看一下`0x546d8`

![image-20250427164256403](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427164256403.png)

跳转过去正在赋值

`a1`来自`a2`，`a2`被传入了函数`sub_539DC`，点进去看看，发现大量的移位，异或等操作，这就是加密的地方

在trace的日志中发现这个函数执行了五次

![image-20250427165447800](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427165447800.png)

看看入参

![image-20250427165551513](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427165551513.png)

![image-20250427165609206](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427165609206.png)

第一次进入`sub_539DC`

![image-20250427180138728](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180138728.png)

![image-20250427180152363](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180152363.png)

第一个参数很像md5的初始化常量，但是顺序被魔改了

正常的初始化常量

```text
A=0x67452301
B=0xefcdab89
C=0x98badcfe
D=0x10325476
```

这里传入的初始化常量

```text
A=0X10325476
B=0X98BADCFE
C=0XEFCDAB89
D=0X67452301
```

第二个参数中出现了大量的0x36

返回值

![image-20250427180220317](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180220317.png)

第二次进入`sub_539DC`

![image-20250427180256868](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180256868.png)

![image-20250427180305790](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180305790.png)

同样的初始化常量

`5C`也是HMAC的特征

返回值

![image-20250427180417888](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180417888.png)

第三次进入`sub_539DC`

![image-20250427180536990](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180536990.png)

![image-20250427180829603](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180829603.png)

传入的第一个参数用到了第一次md5的结果，第二个参数是要加密的字符串

返回值
![image-20250427180949402](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427180949402.png)

第四次进入`sub_539DC`

![image-20250427181146090](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427181146090.png)

![image-20250427181214549](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427181214549.png)

第一个参数是第三次的MD5结果，第二个参数明显可以看到填充特征`0x80`，以及最后八个字节消息长度，注意是小端序，那么长度为`0x30e8`。

返回值

![image-20250427181539578](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427181539578.png)

第五次进入`sub_539DC`

![image-20250427181613297](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427181613297.png)

![image-20250427181713606](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427181713606.png)

第一个参数是第二次的返回值，第二个参数是第四次的返回值以及填充

返回值

![image-20250427182017770](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427182017770.png)

返回值正是我们要找的数据。

分析一下加密流程

- 第一次将HMAC的密钥与0x36异或生成扩展密钥1，由于恰好扩展密钥1长度为64字节，恰好为一个分组，那么可以先计算出第一次md5结果，称为`md5-1`
- 第二次将HMAC的密钥与0x36异或生成扩展密钥2，由于恰好扩展密钥2长度为64字节，恰好为一个分组，那么可以先计算出第一次md5结果，称为`md5-2`
- 第三次，回到之前我的文章中介绍，第一次hash的输入是`扩展密钥1 + 输入字符串`,并且md5分组加密，第二组的初始化常量为第一组的md5结果。如此一来，恰好对应第三次的初始化常量为第一次的md5结果。
- 第四次，初始化常量为第三次计算的md5结果，输入为剩余未加密的数据，当函数运行完，至此HMAC的第一次hash完结
- 第五次正是HMAC的第二次hash，第二次hash的输入是`扩展密钥2+第一次哈希`，由于扩展密钥2长度为64字节，恰好为一个分组，那么第一个参数初始化常量不正好是第二次的md5结果吗，再加上第二个参数输入为第一次哈希并且填充。最终得到我们想要的结果。





那么到现在先确定初始化常量是被魔改了的，找来一份标准的md5，将初始化常量修改，并且传进入参，看看是不是这样
入参

![image-20250427182642976](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427182642976.png)

会发现结果不对，说明魔改点不仅仅是初始化常量，分析ida的伪代码。

![image-20250427182906920](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427182906920.png)

仔细分析可以发现，在标准算法中的循环左移变成了循环右移，这不是关键，可能是伪代码的识别问题，但是这里第一个循环右移位数是26，等价于循环左移6位。但在标准的md5算法中，第一个循环左移位数是7。那么循环左移的位数发生了变化，照着伪代码修改循环左移的位数。

会发现修改了循环左移位数还是不行，那么考虑经常遇到的魔改K表

那么通过分析64轮中第一轮的计算情况



![image-20250427184224006](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427184224006.png)



![image-20250427184242562](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427184242562.png)



![image-20250427184304448](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427184304448.png)

![image-20250427184754951](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427184754951.png)



![image-20250427184916839](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427184916839.png)



![image-20250427185134268](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427185134268.png)

从`a = (a + F(b, c, d) + x + ac) & 0xFFFFFFFF`来着手分析

其中`((v3 ^ v4) & v5 ^ v4)`对应着F函数，`v6`对应着a，`v7`来自入参a2，对应着标准代码中的words[0]，那么`result[23]`就是代表从K表中取值了。搜索伪代码发现存在`result[86]`,刚好对应从0-63即64个K值表

K表可以从trace从一个个找，也可以从unidbg中直接打印出来

我选择从unidbg中打印出来

![image-20250427190259436](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427190259436.png)

鼠标放在result上，按下TAB，查看这一行的汇编

![image-20250427190352989](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427190352989.png)

- **ldp**: Load Pair，表示加载一对寄存器值
- **w27, w30**: 目标寄存器，表示将数据加载到 32 位寄存器 w27 和 w30 中（w 表示 32 位，相对于 64 位的 x 寄存器）。

那么在`0X53D5C`处下断，`x0`里就是我们的K表了

![image-20250427190615306](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427190615306.png)

第一行是不是很熟悉，说明传入的第一个参数里面除了包含初始化常量，还包含了K表

将K表拿下来，替换标准md5，照着伪代码改，注意在第二大轮中的第一轮，第四轮，第十四轮K值还分别与`0xFF00FF00`,`FF0011FF`,`0xFF110011`

![image-20250427214830677](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427214830677.png)

![image-20250427214904199](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427214904199.png)

![image-20250427214931808](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427214931808.png)

然而，改完之后，发现MD5的结果还是不对。

那么尝试在四大轮，每一轮结束后打印`A,B,C,D`的值，然后再trace中搜索

搜索发现第一，第二大轮的结果能搜索到，第三大轮开始就搜索不到，那么问题就出现在这之间了，继续缩小范围

缩小到第40轮时，发现B值无法在trace中搜索到

通过对上面正确的轮加密进行变量重命名
![image-20250427222750153](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427222750153.png)

`v102`的值应该是A，重复此操作，会发现40轮与41轮发生了交换，42与43轮发生了交换

其实使用上面修改完的MD5实现还原时，会发现前面两次函数进入的结果都对，第三次传入的字符串不对，最终发现填充也发生了魔改，最后的消息长度会加上一个分组的长度。





到此md5还原成功。



还剩下HMAC的key不知道是怎么来的

### AES

![image-20250427232604700](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427232604700.png)

现在就变成了寻找这一段数据

![image-20250427232643608](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427232643608.png)

在unidbg中看看日志

![image-20250427232905364](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427232905364.png)



trace这一段内存的写入

```java
emulator.traceWrite(0x4045e010, 0x4045e010+64);
```



![image-20250427232842916](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250427232842916.png)

跳转过去看看汇编

![image-20250428151559540](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428151559540.png)

看不懂思密达，问一下AI

![image-20250428151701325](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428151701325.png)

那么`Q0`的值就是来自于`Q0`与`Q1`的异或，在trace文件中可以看到这一地址执行了6次，可惜在trace的文件中无法看到Q系列寄存器，没事，下断点看

```java
Debugger debugger = emulator.attach();
debugger.addBreakPoint(module.base + 0x52A68);
```

在python中打印结果

![image-20250428152802524](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428152802524.png)

![image-20250428152825993](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428152825993.png)

正是我们需要的结果，不过是反着来的

那么我们就需要找到前面异或的数据是怎么来的

别忘了前面传入的数据还没用到从`SharedPreferences`读取到的`main-hmac`

![image-20250428153056714](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428153056714.png)

正是输入的右边部分

在这里`a6`正是加密函数

![image-20250428162626552](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428162626552.png)

可是跳转不过去

在trace中找到这一行的地址，跳转过去

![image-20250428162708119](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428162708119.png)

看一下输入

![image-20250428162914605](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428162914605.png)

x0是不是很熟悉

![image-20250428162949317](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428162949317.png)

x1看不出来什么

![image-20250428163022495](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/image-20250428163022495.png)

x2 的大小`16 * 11 = 176`字节，这不正好是AES扩展后的11个密钥吗？

不建议照着标准AES改，后面的魔改AES就得照着IDA跟trace扣代码了，最后剩下体力活

