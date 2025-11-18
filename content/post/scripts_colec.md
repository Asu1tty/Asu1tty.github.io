---
date: '2025-11-17T11:48:50+08:00'
draft: false
title: '脚本记录'
tags:
  - Scripts
categories:
  - Scripts

---

## 1. Java 层
### 1.1. hashmap 相关的hook
```java
//由于有些请求头会使用这个添加，可能通过okhttp直接增加
var hashMap = Java.use("java.util.HashMap");
hashMap.put.implementation = function (a, b) {
    console.log("hashMap.put: ", a, b);
    return this.put(a, b);
}

// java.util.concurrent.ConcurrentHashMap
var ConcurrentHashMap = Java.use("java.util.concurrent.ConcurrentHashMap");
ConcurrentHashMap.put.implementation = function (a, b) {
    console.log("ConcurrentHashMap.put: ", a, b);
    return this.put(a, b);
}

// java.util.LinkedHashMap
var LinkedHashMapClass = Java.use("java.util.LinkedHashMap");
LinkedHashMapClass.put.implementation = function (key, value) {
    console.log("LinkedHashMap key:", key, "value:", value);
    return this.put(key, value);
};
```
### 1.2. URL相关hook
```java
// hook java.net.URL
var URL = Java.use('java.net.URL');
URL.$init.overload('java.lang.String').implementation = function (a) {
    console.log('java.net.URL ' + a)
    this.$init(a)
}

//hook okhttp3 HttpUrl
var Builder = Java.use('okhttp3.Request$Builder');
Builder.url.overload('okhttp3.HttpUrl').implementation = function (a) {
    var res = this.url(a);
    console.log("okhttp3.HttpUrl result: " + res)
    return res;
}
```

### 1.3. okhttp 拦截器
```javascript
function showStacks() {
    var Exception = Java.use("java.lang.Exception");
    var ins = Exception.$new("Exception");
    var straces = ins.getStackTrace();

    if (undefined == straces || null == straces) {
        return;
    }

    console.log("============================= Stack strat=======================");
    console.log("");

    for (var i = 0; i < straces.length; i++) {
        var str = "   " + straces[i].toString();
        console.log(str);
    }

    console.log("");
    console.log("============================= Stack end=======================\r\n");
    Exception.$dispose();
}
Java.perform(function () {
    try {
        const array_list = Java.use("java.util.ArrayList");
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
            // console.log('  --> Bypassing TrustManagerImpl checkTrusted ');
            return array_list.$new();
        }
        // console.log('[+] TrustManagerImpl');
    } catch (err) {
        // console.log('[ ] TrustManagerImpl');
    }



    try {
        // Bypass OkHTTPv3 {4}
        const okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_4['check$okhttp'].implementation = function (a, b) {
            //    console.log('  --> Bypassing OkHTTPv3 ($okhttp): ' + a);
            return;
        };
        // console.log('[+] OkHTTPv3 ($okhttp)');
    } catch (err) {
        //    console.log('[ ] OkHTTPv3 ($okhttp)');
    }
    // 抓取 HttpURLConnection 请求和响应
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.getInputStream.implementation = function () {
        var url = this.getURL().toString();
        var method = this.getRequestMethod();
        console.log('[*] HTTP Request: ' + method + ' ' + url);

        // 打印请求头
        var headers = this.getRequestProperties();
        showStacks()
        headers.keySet().toArray().forEach(function (key) {
            var values = headers.get(key).toArray().join(', ');
            console.log('[*] Header: ' + key + ': ' + values);
        });

        // 打印请求体
        if (this.getDoOutput()) {
            var outputStream = this.getOutputStream();
            var writer = new Java.use('java.io.OutputStreamWriter')(outputStream);
            var body = this.getLocalData().toString();
            console.log('[*] Body: ' + body);
        }

        var inputStream = this.getInputStream();

        // 读取响应
        var reader = new Java.use('java.io.InputStreamReader')(inputStream);
        var bufferedReader = new Java.use('java.io.BufferedReader')(reader);
        var response = '';
        var line;
        while ((line = bufferedReader.readLine()) !== null) {
            response += line + '\n';
        }
        console.log('[*] HTTP Response: ' + response);
        return inputStream;
    };

    // 抓取 OkHttp 请求和响应
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var OkHttpClientBuilder = Java.use('okhttp3.OkHttpClient$Builder');
        var Interceptor = Java.use('okhttp3.Interceptor');
        var Response = Java.use('okhttp3.Response');
        var ResponseBody = Java.use('okhttp3.ResponseBody');

        // 创建自定义的 Interceptor 实现
        var MyInterceptor = Java.registerClass({
            name: 'com.custom.MyInterceptor',
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    try {
                        var request = chain.request();
                        var url = request.url().toString();
                        var method = request.method();

                        console.log('[*] OkHttp Request: ' + method + ' ' + url);

                        var headers = request.headers();
                        showStacks()
                        for (var i = 0; i < headers.size(); i++) {
                            console.log('[*] Header: ' + headers.name(i) + ': ' + headers.value(i));
                        }

                        var body = request.body();
                        if (body) {
                            var buffer = Java.use('okio.Buffer').$new();
                            body.writeTo(buffer);
                            var requestBody = buffer.readUtf8();
                            console.log('[*] Body: ' + requestBody);
                        }

                        var response = chain.proceed(request);

                        // 打印响应
                        var responseBody = response.body().string();
                        console.log('[*] OkHttp Response: ' + responseBody);

                        // 需要重新创建响应，因为 response.body().string() 会消耗掉响应体
                        var newResponseBody = ResponseBody.create(response.body().contentType(), responseBody);
                        var newResponse = response.newBuilder()
                            .body(newResponseBody)
                            .build();

                        return newResponse;
                    } catch (e) {
                        console.log('Interceptor Error: ' + e);
                        throw e;
                    }
                }
            }
        });

        // 重载 OkHttpClient.Builder 的 build 方法
        OkHttpClientBuilder.build.overload().implementation = function () {
            console.log('[*] Adding interceptor to OkHttpClient');
            this.addInterceptor(MyInterceptor.$new());
            return this.build();
        };

        console.log('Script successfully loaded');
    } catch (e) {
        console.log('Error: ' + e);
    }
});

```

### 1.4. JSON相关
```javascript
// JSON处理
var jSONObject = Java.use("org.json.JSONObject");
jSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function (a, b) {
    console.log("jSONObject.put: ", a, b);
    return this.put(a, b);
}
jSONObject.getString.implementation = function (a) {
    console.log("jSONObject.getString: ", a);
    var result = this.getString(a);
    console.log("jSONObject.getString result: ", result);
    return result;
}
JSONObject['optString'].overload('java.lang.String').implementation = function (str) {
    if(str === "data"){
        console.log('str', str)
        getStackTraceString();
    }
    let result = this['optString'](str);
    return result;
};
```

### 1.5. 弹窗
```JavaScript
// 弹窗关键类
var toast = Java.use("android.widget.Toast");
toast.show.implementation = function () {
    console.log("toast.show: ");
    return this.show();
}

Java.perform(function() {
    var Dialog = Java.use("android.app.Dialog");
    // Hook show() 方法
    Dialog.show.implementation = function() {
        this.show();
    };
});

var Toast = Java.use("android.widget.Toast");
Toast.makeText.overload("android.content.Context", "java.lang.CharSequence", "int").implementation = function (context, text, duration) {
    console.log("Toast message:", text);
    // 调用原始 makeText 方法生成 Toast
    var toast = this.makeText(context, text, duration);
    // 返回生成的 Toast 对象
    return toast;
};
```

### 1.6. SharedPreferences类相关
```JavaScript
// hook内部存储api，打印出存储的数据
var sp = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
sp.putBoolean.overload('java.lang.String', 'boolean').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl ] putBoolean -> key: "+arg1+" = "+arg2);
    return this.putBoolean(arg1,arg2);
}

sp.putString.overload('java.lang.String', 'java.lang.String').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putString -> key: "+arg1+" = "+arg2);
    return this.putString(arg1,arg2);
}

sp.putInt.overload('java.lang.String', 'int').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putInt -> key: "+arg1+" = "+arg2);
    return this.putInt(arg1,arg2);
}

sp.putFloat.overload('java.lang.String', 'float').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putFloat -> key: "+arg1+" = "+arg2);
    return this.putFloat(arg1,arg2);
}

sp.putLong.overload('java.lang.String', 'long').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putLong -> key: "+arg1+" = "+arg2);
    return this.putLong(arg1,arg2);
}

// hook应用程序间数据传递的api，打印出传递数据的uri与具体的字段
var content = Java.use("android.content.ContentResolver");
content.insert.overload("android.net.Uri","android.content.ContentValues").implementation = function(arg1,arg2){
    console.log("[ContentResolver] *insert -> Uri: "+arg1+"  Values: "+arg2);
    return this.insert(arg1,arg2);
}

content.delete.overload("android.net.Uri","java.lang.String","[Ljava.lang.String;").implementation = function(arg1,arg2,arg3){
    console.log("[ContentResolver] *delete -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3);
    return this.delete(arg1,arg2,arg3);
}

content.update.overload('android.net.Uri','android.content.ContentValues','java.lang.String','[Ljava.lang.String;').implementation = function(arg1,arg2,arg3,arg4){
    console.log("[ContentResolver] *update -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4);
    return this.update(arg1,arg2,arg3,arg4);
}

content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function(arg1,arg2,arg3,arg4){
    console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4);
    return this.query(arg1,arg2,arg3,arg4);
}

content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(arg1,arg2,arg3,arg4,arg5){
    console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4+"\n  -> arg5: "+arg5);
    return this.query(arg1,arg2,arg3,arg4,arg5);
}

content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(arg1,arg2,arg3,arg4,arg5,arg6){
    console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4+"\n  -> arg5: "+arg5+"\n arg6: "+arg6);
    return this.query(arg1,arg2,arg3,arg4,arg5,arg6);
}
```

### 1.7. USB 检测
```JavaScript
function usb_anti() {
    Java.enumerateClassLoadersSync().forEach(classLoader => {
        Java.classFactory.loader = classLoader
        let ArrayList = Java.use("java.util.ArrayList");
        let AccessibilityManager = Java.use("android.view.accessibility.AccessibilityManager");
        AccessibilityManager["getInstalledAccessibilityServiceList"].implementation = function () {
            return ArrayList.$new();
        };

        AccessibilityManager["getEnabledAccessibilityServiceList"].implementation = function (i) {
            return ArrayList.$new();
        };

        let Global = Java.use("android.provider.Settings$Global");
        Global["getInt"].overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr, s, i) {
            let ret = this["getInt"](cr, s, i);
            if (s === "adb_enabled" || s === "adb_wifi_enabled" || s === "development_settings_enabled" || s === "device_provisioned") {
                console.log("hook usb")
                ret = 0;
            }
            return ret;
        };

        let Secure = Java.use("android.provider.Settings$Secure");
        Secure["getInt"].overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr, s, i) {
            let ret = this["getInt"](cr, s, i);
            if (s === "adb_enabled" || s === "adb_wifi_enabled" || s === "development_settings_enabled" || s === "device_provisioned") {
                console.log("hook usb")
                ret = 0;
            }
            return ret;
        };
    })
    console.log("[ * ] USB调试检测Hook完成");
}
```

### 1.8. hook 动态加载的类dex

可以 hook 动态加载的 inMemoryClassloder 加载的方法
```javascript
function hookClassMethod(className, methodName) {
    let hooked = false;
    function attemptHook() {
        if (hooked) return;
        Java.perform(function() {
            try {
                let ret = null;
                // Phase 1: 默认loader
                try {
                    const ldr = Java.classFactory.loader;
                    ldr.loadClass(className);
                    ret = Java.use(className);
                } catch (_) {
                    // Phase 2: 枚举所有ClassLoader
                    let targetLoader = null;
                    Java.enumerateClassLoaders({
                        onMatch(ldr) {
                            try {
                                ldr.loadClass(className);
                                targetLoader = ldr;
                                return "stop";
                            } catch (_) {}
                        },
                        onComplete() {}
                    });
                    if (targetLoader) {
                        ret = Java.ClassFactory.get(targetLoader).use(className);
                    }
                }
                
                if (ret) {
                    if (methodName === "constructors") {
                        // Hook所有构造方法
                        try {
                            const constructorOverloads = ret.$init.overloads;
                            if (constructorOverloads && constructorOverloads.length > 0) {
                                for (let i = 0; i < constructorOverloads.length; i++) {
                                    const overload = constructorOverloads[i];
                                    overload.implementation = function(...args) {
                                        console.log(`${className}.<init>[${i}] constructor called with ${args.length} args: ${args}`);
                                        let result = this.$init(...args);
                                        console.log(`${className}.<init>[${i}] constructor completed`);
                                        return result;
                                    };
                                }
                                console.log(`[+] Hooked ${constructorOverloads.length} constructor(s) for ${className}`);
                            } else {
                                // 如果没有overloads属性，直接hook $init
                                ret.$init.implementation = function(...args) {
                                    console.log(`${className}.<init> constructor called: ${args}`);
                                    let result = this.$init(...args);
                                    console.log(`${className}.<init> constructor completed`);
                                    return result;
                                };
                                console.log(`[+] Hooked constructor for ${className}`);
                            }
                            hooked = true;
                        } catch (constructorError) {
                            console.log(`[-] Failed to hook constructors for ${className}: ${constructorError}`);
                        }
                    } else {
                        // Hook普通方法
                        ret[methodName].implementation = function(...args) {
                            console.log(`${className}.${methodName} is called: ${args}`);
                            let result = this[methodName](...args);
                            console.log(`${className}.${methodName} result=${result}`);
                            return result;
                        };
                        console.log(`[+] Hooked ${className}.${methodName}`);
                        hooked = true;
                    }
                }
            } catch (e) {
                // 继续重试
                console.log(`[-] Hook attempt failed: ${e}`);
            }
        });
        if (!hooked) {
            setTimeout(attemptHook, 300);
        }
    }
    attemptHook();
}

// 使用示例
// Hook普通方法
// hookClassMethod("com.taobao.wireless.security.adapter.JNICLibrary", "doCommandNative");

// Hook构造方法
hookClassMethod("com.ucweb.upgrade.UpgradeResponse", "constructors");
```

### 1.9. 获取 native 函数动态注册地址
```JavaScript
/**
 * 查找指定类和方法名对应的 native 函数地址（排除 CheckJNI 包装版本）
 *
 * @param {string} soName             - 包含目标 native 方法的 so 库名（如 "libandroid_runtime.so"）
 * @param {string} javaClassName      - Java 类名（如 "android.os.Process"）
 * @param {string} targetMethodName   - 方法名（如 "getUidForName"）
 * @returns {NativePointer|null}      - 找到的 native 函数地址或 null
 */
function findNativeAddress(soName, javaClassName, targetMethodName) {
    // 获取指定 so 中的导出符号列表
    const exports = Module.enumerateExportsSync(soName);

    // 将 Java 类名转为 native C++ 符号格式（如 android_os_Process）
    const lowerClassName = javaClassName.replace(/\./g, "_");

    // 遍历导出符号，寻找符合条件的 native 方法
    for (let exp of exports) {
        if (
            exp.type === "function" &&
            exp.name.indexOf(lowerClassName) !== -1 && // 包含类名
            exp.name.indexOf(targetMethodName) !== -1 && // 包含方法名
            exp.name.indexOf("CheckJNI") === -1 // 排除 CheckJNI 包装版本
        ) {
            console.log(`[+] Found native method: ${exp.name} @ ${exp.address}`);
            return ptr(exp.address); // 找到匹配的符号地址
        }
    }

    // 未找到匹配的符号
    return null;
}

/**
 * 找到 entry_point_from_jni_ 在 ArtMethod 结构体中的偏移量（根据 Android 版本不同可能会变化）
 *
 * @returns {number} 返回 entry_point_from_jni_ 的偏移量，若未找到返回 -1
 */
function entryPointFromJniOffset() {
    // 1. 选择一个已知的 Java native 方法作为“参考样本”。 该方法需要在系统中真实存在并且能找到其 native 地址。
    const soName = "libandroid_runtime.so";
    const className = "android.os.Process";
    const methodName = "getUidForName";

    // 2. 查找对应的 native 函数地址
    const native_addr = findNativeAddress(soName, className, methodName);
    if (native_addr === null) {
        console.log("[-] Native function not found.");
        return -1;
    }

    let clazz = Java.use(className).class;
    let methods = clazz.getDeclaredMethods();

    // 3. 获取类中所有方法并筛选 native 方法
    for (let i = 0; i < methods.length; i++) {
        // 获取方法签名
        let methodName = methods[i].toString();

        // 获取方法的修饰符，如 public、private、static、native 等
        let flags = methods[i].getModifiers();

        // 256 代表 native 修饰符
        if (flags & 256) {
            // 如果方法名中包含 methodName 说明找到了目标方法
            if (methodName.indexOf("getUidForName") != -1) {
                // 4. 获取 ArtMethod 指针并逐字节扫描字段
                let art_method = methods[i].getArtMethod();

                for (let j = 0; j < 30; j = j + 1) {
                    let jni_entrypoint_offset = Memory.readPointer(ptr(art_method + j));

                    // 比较每个字段的值是否等于我们前面获取到的 native 函数地址。
                    if (native_addr.equals(jni_entrypoint_offset)) {
                        // 找到即返回偏移
                        return j;
                    }
                }
            }
        }
    }

    // 未找到 JNI 方法对应的偏移量，返回 -1
    return -1;
}

/**
 * Phase 1: 主 ClassLoader（最热门）
 * Phase 2: 枚举所有 ClassLoader, enumerateClassLoaders（InMemory、加密 so...）
 *
 * 返回 [JavaClass, ClassLoader]
 */
function getClassAndLoaderFast(className) {
    // ⬇︎ 把 Java.perform 提到这里并同步返回值
    let ret = null;
    Java.perform(function() {
        // ----- Phase 1 -----
        try {
            const ldr = Java.classFactory.loader;
            ldr.loadClass(className); // 直接抛异常就走 catch
            ret = [Java.use(className), ldr];
            return; // 跳出 Java.perform
        } catch (_) {
            /* ignore */
        }

        // ----- Phase 2 -----
        let last = null;
        Java.enumerateClassLoaders({
            onMatch(ldr) {
                try {
                    ldr.loadClass(className);
                    last = ldr;
                    return "stop";
                } catch (_) {}
            },
            onComplete() {},
        });
        if (last) {
            ret = [Java.ClassFactory.get(last).use(className), last];
        } else {
            throw new Error(`Class ${className} not found`);
        }
    });
    return ret; // 一定要在 Java.perform 块外返回
}

/**
 * 遍历类中的 native 方法，打印 JNI 函数地址、所属模块信息，结构化输出。
 *
 * @param {string} className - Java 类名（如 "android.os.Process"）
 */
function getJniMethodAddr(className) {
    Java.perform(function() {
        const [clsObj] = getClassAndLoaderFast(className); // 这里就不会为 undefined
        const clazz = clsObj.class;
        const jni_entrypoint_offset = entryPointFromJniOffset();

        console.log("========== [ JNI Method Info Dump ] ==========");
        console.log("[*] Target class: " + className);
        console.log(
            "[*] entry_point_from_jni_ offset = " + jni_entrypoint_offset + " bytes\n"
        );

        const methods = clazz.getDeclaredMethods();
        let count = 0;

        for (let i = 0; i < methods.length; i++) {
            const m = methods[i];
            const flags = m.getModifiers();
            const methodName = m.toString();

            // 256 表示 native 方法
            if ((flags & 256) !== 0) {
                count++;
                const art_method = m.getArtMethod();
                const native_addr = Memory.readPointer(
                    ptr(art_method).add(jni_entrypoint_offset)
                );
                let module = null;
                try {
                    module = Process.getModuleByAddress(native_addr);
                } catch (error) {
                    console.error("error: ", error);
                }

                // 结构化打印信息
                console.log(
                    "------------ [ #" + count + " Native Method ] ------------"
                );
                console.log("JavaMethod Name       : " + methodName);
                console.log("ArtMethod Ptr         : " + ptr(art_method));
                console.log("Native Addr           : " + native_addr);
                if (module) {
                    const offset = native_addr.sub(module.base);
                    const debugSymbol_name = DebugSymbol.fromAddress(
                        ptr(native_addr)
                    ).name;
                    console.log("NativeMethod Name     : " + debugSymbol_name);
                    console.log("Module Name           : " + module.name);
                    console.log("Native Offset         : 0x" + offset.toString(16));
                    console.log("Module Base           : " + module.base);
                    console.log("Module Size           : " + module.size + " bytes");
                    console.log("Module Path           : " + module.path);
                } else {
                    console.log(
                        "Module Info           : [ Not Found, Maybe Anonymous Map ]"
                    );
                    let pid = Process.id;
                    console.log(`Please check -------->  cat /proc/${pid}/maps`);
                }
                console.log("------------------------------------------------\n");
            }
        }

        if (count === 0) {
            console.log("[-] No native methods found in class: " + className);
        } else {
            console.log("[*] Total native methods found: " + count);
        }

        console.log("===============================================");
    });
}

/* Usage: frida -UF -l so_register.js
          frida -U -f com.xxx.xx -l so_register.js
          getJniMethodAddr(className)  //className is where function binded

*/
```
