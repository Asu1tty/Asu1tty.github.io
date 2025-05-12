---
date: '2025-05-01T11:20:50+08:00'
draft: false
title: 'Android so加载源码分析与加壳技术'
tags:
  - Android
categories:
  - AOSP

---

本次分析AOSP 的源码的安卓版本为 `android-12.0.0_r34`

## 1. java层调用
So在java层的加载方式有两种
```java
System.loadLibrary(String libName)
```
或
```java
System.load(String path)
```

### 1.1. System.load()
这里我们以`System.load`作为分析入口
```java
// libcore/ojluni/src/main/java/java/lang/System.java
/**
     * Loads the native library specified by the filename argument.  The filename
     * argument must be an absolute path name.
     *
     * If the filename argument, when stripped of any platform-specific library
     * prefix, path, and file extension, indicates a library whose name is,
     * for example, L, and a native library called L is statically linked
     * with the VM, then the JNI_OnLoad_L function exported by the library
     * is invoked rather than attempting to load a dynamic library.
     * A filename matching the argument does not have to exist in the
     * file system.
     * See the JNI Specification for more details.
     *
     * Otherwise, the filename argument is mapped to a native library image in
     * an implementation-dependent manner.
     *
     * <p>
     * The call <code>System.load(name)</code> is effectively equivalent
     * to the call:
     * <blockquote><pre>
     * Runtime.getRuntime().load(name)
     * </pre></blockquote>
     *
     * @param      filename   the file to load.
     * @exception  SecurityException  if a security manager exists and its
     *             <code>checkLink</code> method doesn't allow
     *             loading of the specified dynamic library
     * @exception  UnsatisfiedLinkError  if either the filename is not an
     *             absolute path name, the native library is not statically
     *             linked with the VM, or the library cannot be mapped to
     *             a native library image by the host system.
     * @exception  NullPointerException if <code>filename</code> is
     *             <code>null</code>
     * @see        java.lang.Runtime#load(java.lang.String)
     * @see        java.lang.SecurityManager#checkLink(java.lang.String)
     */
    @CallerSensitive
    public static void load(String filename) {
        Runtime.getRuntime().load0(Reflection.getCallerClass(), filename);
    }
```
其中，`Reflection.getCallerClass()` 是一个内部方法，定义在 `sun.reflect.Reflection` 类中（属于 JDK/ART 的私有 API）。它的作用是**返回调用当前方法的类的 `Class` 对象**，即调用栈中调用者的类。
```text
Class A -> calls System.load() -> calls Runtime.load0()
```
在 `System.load()` 方法中，`Reflection.getCallerClass()` 返回的是调用 `System.load()` 的类（例如 `Class A`）的 `Class` 对象。`Reflection.getCallerClass()` 会检查调用栈，跳过当前方法（`System.load`）和其直接调用者（`Runtime.getRuntime().load0`）所在的类，找到更上层的调用者类。
### 1.2. Runtime.getRuntime().load0()
在`Runtime.getRuntime().load0()`中进行了 `filename` 是否是 绝对路径 以及 空字符串 的检查之后，便开始调用 `nativeLoad` 真正的去加载 so 了
```java
// libcore/ojluni/src/main/java/java/lang/Runtime.java
synchronized void load0(Class<?> fromClass, String filename) {
        if (!(new File(filename).isAbsolute())) {
            throw new UnsatisfiedLinkError(
                "Expecting an absolute path of the library: " + filename);
        }
        if (filename == null) {
            throw new NullPointerException("filename == null");
        }
        String error = nativeLoad(filename, fromClass.getClassLoader());
        if (error != null) {
            throw new UnsatisfiedLinkError(error);
        }
    }
```

### 1.3. Runtime.java 中的 nativeLoad()
在`java`层的`nativeLoad()`调用了`native`层的`nativeLoad()`，从这里正式进入native层部分
```java
// libcore/ojluni/src/main/java/java/lang/Runtime.java
private static String nativeLoad(String filename, ClassLoader loader) {
	return nativeLoad(filename, loader, null);
}
private static native String nativeLoad(String filename, ClassLoader loader, Class<?> caller);
```

## 2. so层调用
### 2.1. Runtime.c 中的 nativeLoad()
调用了`JVM_NativeLoad()`
```c
// libcore/ojluni/src/main/native/Runtime.c
JNIEXPORT jstring JNICALL
Runtime_nativeLoad(JNIEnv* env, jclass ignored, jstring javaFilename,
                   jobject javaLoader, jclass caller)
{
    return JVM_NativeLoad(env, javaFilename, javaLoader, caller);
}
```

### 2.2. JVM_NativeLoad()
调用了`LoadNativeLibrary()`
```c
// android-platform\art\openjdkjvm\OpenjdkJvm.cc
JNIEXPORT jstring JVM_NativeLoad(JNIEnv* env,
                                 jstring javaFilename,
                                 jobject javaLoader,
                                 jclass caller) {
  // 实例化一个文件对象                               
  ScopedUtfChars filename(env, javaFilename);
  if (filename.c_str() == nullptr) {
    return nullptr;
  }

  std::string error_msg;
  {
    // 获取当前进程的 javaVM 对象
    art::JavaVMExt* vm = art::Runtime::Current()->GetJavaVM();
    bool success = vm->LoadNativeLibrary(env,
                                         filename.c_str(),
                                         javaLoader,
                                         caller,
                                         &error_msg);
    if (success) {
      return nullptr;
    }
  }

  // Don't let a pending exception from JNI_OnLoad cause a CheckJNI issue with NewStringUTF.
  env->ExceptionClear();
  return env->NewStringUTF(error_msg.c_str());
```

### 2.3. LoadNativeLibrary()
`LoadNativeLibrary`的代码较长，分段分析
#### 2.3.1. 初始检查和重复加载检查
使用 `Thread::Current()` 获取当前线程。通过互斥锁 `MutexLock` 保护对共享库列表的访问（`libraries_` 是一个全局映射，存储已加载的库）。`libraries_->Get(path)` 检查指定路径的库是否已加载，若已加载，则返回对应的 `SharedLibrary` 对象，否则返回 `nullptr`。
```cpp
// art/runtime/jni/java_vm_ext.cc
error_msg->clear();

// See if we've already loaded this library.  If we have, and the class loader
// matches, return successfully without doing anything.
// TODO: for better results we should canonicalize the pathname (or even compare
// inodes). This implementation is fine if everybody is using System.loadLibrary.
SharedLibrary* library;
Thread* self = Thread::Current();
{
// TODO: move the locking (and more of this logic) into Libraries.
MutexLock mu(self, *Locks::jni_libraries_lock_);
library = libraries_->Get(path);
}
```


#### 2.3.2. 类加载器和分配器的处理
`class_linker->IsBootClassLoader(soa, loader.Ptr())` 检查是否为引导类加载器（BootClassLoader）。特殊处理 BootClassLoader，并获取调用者类的 Dex 文件路径
```cpp
// art/runtime/jni/java_vm_ext.cc
void* class_loader_allocator = nullptr;
std::string caller_location;
{
    ScopedObjectAccess soa(env);
    ObjPtr<mirror::ClassLoader> loader = soa.Decode<mirror::ClassLoader>(class_loader);

    ClassLinker* class_linker = Runtime::Current()->GetClassLinker();
    if (class_linker->IsBootClassLoader(soa, loader.Ptr())) {
      loader = nullptr;
      class_loader = nullptr;
      if (caller_class != nullptr) {
        ObjPtr<mirror::Class> caller = soa.Decode<mirror::Class>(caller_class);
        ObjPtr<mirror::DexCache> dex_cache = caller->GetDexCache();
        if (dex_cache != nullptr) {
          caller_location = dex_cache->GetLocation()->ToModifiedUtf8();
        }
      }
    }

    class_loader_allocator = class_linker->GetAllocatorForClassLoader(loader.Ptr());
    CHECK(class_loader_allocator != nullptr);
}
```


#### 2.3.3. 处理已加载的库
如果库已加载（library != nullptr），比较其分配器与当前类加载器的分配器,,如果请求加载的 ClassLoader 与之前加载的不同（通过比较分配器标识判断），则构造一个详细的错误信息，记录警告日志，并返回加载失败。
```cpp
// art/runtime/jni/java_vm_ext.cc
if (library != nullptr) {
    if (library->GetClassLoaderAllocator() != class_loader_allocator) {
        auto call_to_string = [&](jobject obj) -> std::string {
            if (obj == nullptr) return "null";
            ScopedLocalRef<jobject> local_ref(env, env->NewLocalRef(obj));
            if (local_ref != nullptr) {
                ScopedLocalRef<jclass> local_class(env, env->GetObjectClass(local_ref.get()));
                jmethodID to_string = env->GetMethodID(local_class.get(), "toString", "()Ljava/lang/String;");
                ScopedLocalRef<jobject> local_string(env, env->CallObjectMethod(local_ref.get(), to_string));
                if (local_string != nullptr) {
                    ScopedUtfChars utf(env, reinterpret_cast<jstring>(local_string.get()));
                    if (utf.c_str() != nullptr) return utf.c_str();
                }
                if (env->ExceptionCheck()) {
                    env->ExceptionDescribe();
                    env->ExceptionClear();
                }
                return "(Error calling toString)";
            }
            return "null";
        };
        std::string old_class_loader = call_to_string(library->GetClassLoader());
        std::string new_class_loader = call_to_string(class_loader);
        StringAppendF(error_msg, "Shared library \"%s\" already opened by "
            "ClassLoader %p(%s); can't open in ClassLoader %p(%s)",
            path.c_str(), library->GetClassLoader(), old_class_loader.c_str(),
            class_loader, new_class_loader.c_str());
        LOG(WARNING) << *error_msg;
        return false;
    }
    VLOG(jni) << "[Shared library \"" << path << "\" already loaded in ClassLoader " << class_loader << "]";
    if (!library->CheckOnLoadResult()) {
        StringAppendF(error_msg, "JNI_OnLoad failed on a previous attempt to load \"%s\"", path.c_str());
        return false;
    }
    return true;
}
```

#### 2.3.4. 加载新库OpenNativeLibrary
这部分代码在 library == nullptr 时执行，即库尚未被加载。正是我们需要分析的部分，**`android::OpenNativeLibrary`** 调用底层 dlopen 打开本地库，传入参数包括目标 SDK 版本、路径、类加载器等。
```cpp
// art/runtime/jni/java_vm_ext.cc
// Open the shared library.  Because we're using a full path, the system
  // doesn't have to search through LD_LIBRARY_PATH.  (It may do so to
  // resolve this library's dependencies though.)

  // Failures here are expected when java.library.path has several entries
  // and we have to hunt for the lib.

  // Below we dlopen but there is no paired dlclose, this would be necessary if we supported
  // class unloading. Libraries will only be unloaded when the reference count (incremented by
  // dlopen) becomes zero from dlclose.

  // Retrieve the library path from the classloader, if necessary.
  ScopedLocalRef<jstring> library_path(env, GetLibrarySearchPath(env, class_loader));

  Locks::mutator_lock_->AssertNotHeld(self);
  const char* path_str = path.empty() ? nullptr : path.c_str();
  bool needs_native_bridge = false;
  char* nativeloader_error_msg = nullptr;
  void* handle = android::OpenNativeLibrary(
      env,
      runtime_->GetTargetSdkVersion(),
      path_str,
      class_loader,
      (caller_location.empty() ? nullptr : caller_location.c_str()),
      library_path.get(),
      &needs_native_bridge,
      &nativeloader_error_msg);
  VLOG(jni) << "[Call to dlopen(\"" << path << "\", RTLD_NOW) returned " << handle << "]";

  if (handle == nullptr) {
    *error_msg = nativeloader_error_msg;
    android::NativeLoaderFreeErrorMessage(nativeloader_error_msg);
    VLOG(jni) << "dlopen(\"" << path << "\", RTLD_NOW) failed: " << *error_msg;
    return false;
  }

  if (env->ExceptionCheck() == JNI_TRUE) {
    LOG(ERROR) << "Unexpected exception:";
    env->ExceptionDescribe();
    env->ExceptionClear();
  }
```
#### 2.3.5. 创建 SharedLibrary 对象
构造一个 SharedLibrary 对象，包含库的路径、句柄等信息。在锁内检查是否其他线程已添加该库。如果没有（`library == nullptr`），将新库加入 `libraries_`。若输掉竞争（!created_library），说明其他线程已添加库，返回已有库的加载结果。
```cpp
// art/runtime/jni/java_vm_ext.cc
bool created_library = false;
{
    std::unique_ptr<SharedLibrary> new_library(
        new SharedLibrary(env, self, path, handle, needs_native_bridge, class_loader, class_loader_allocator));
    MutexLock mu(self, *Locks::jni_libraries_lock_);
    library = libraries_->Get(path);
    if (library == nullptr) {
      library = new_library.release();
      libraries_->Put(path, library);
      created_library = true;
    }
}
if (!created_library) {
    LOG(INFO) << "WOW: we lost a race to add shared library: " << "\"" << path << "\" ClassLoader=" << class_loader;
    return library->CheckOnLoadResult();
}
VLOG(jni) << "[Added shared library \"" << path << "\" for ClassLoader " << class_loader << "]";
```
#### 2.3.6. 调用 JNI_OnLoad
`FindSymbol` 检查库中是否有 `JNI_OnLoad` 函数。
**无 JNI_OnLoad**：直接认为加载成功。
**调用 JNI_OnLoad**：
- 保存并设置类加载器覆盖，确保 `JNI_OnLoad` 使用正确的类加载器。
- 调用 `JNI_OnLoad`，获取返回的 `JNI` 版本号。
- 根据 `SDK` 版本，可能调整信号链（`EnsureFrontOfChain`）。
- 恢复原始类加载器。
**结果判断**：
- 返回 `JNI_ERR`：加载失败。
- 返回错误的 `JNI` 版本：加载失败。
- 否则：加载成功。
**设置并返回结果**：将加载结果存储到 `library` 并返回。
```cpp
// art/runtime/jni/java_vm_ext.cc
bool was_successful = false;
void* sym = library->FindSymbol("JNI_OnLoad", nullptr);
if (sym == nullptr) {
    VLOG(jni) << "[No JNI_OnLoad found in \"" << path << "\"]";
    was_successful = true;
} else {
    ScopedLocalRef<jobject> old_class_loader(env, env->NewLocalRef(self->GetClassLoaderOverride()));
    self->SetClassLoaderOverride(class_loader);
    VLOG(jni) << "[Calling JNI_OnLoad in \"" << path << "\"]";
    using JNI_OnLoadFn = int(*)(JavaVM*, void*);
    JNI_OnLoadFn jni_on_load = reinterpret_cast<JNI_OnLoadFn>(sym);
    int version = (*jni_on_load)(this, nullptr);
    if (IsSdkVersionSetAndAtMost(runtime_->GetTargetSdkVersion(), SdkVersion::kL)) {
        EnsureFrontOfChain(SIGSEGV);
    }
    self->SetClassLoaderOverride(old_class_loader.get());
    if (version == JNI_ERR) {
        StringAppendF(error_msg, "JNI_ERR returned from JNI_OnLoad in \"%s\"", path.c_str());
    } else if (JavaVMExt::IsBadJniVersion(version)) {
        StringAppendF(error_msg, "Bad JNI version returned from JNI_OnLoad in \"%s\": %d", path.c_str(), version);
    } else {
        was_successful = true;
    }
    VLOG(jni) << "[Returned " << (was_successful ? "successfully" : "failure") << " from JNI_OnLoad in \"" << path << "\"]";
}
library->SetResult(was_successful);
return was_successful;
```

### 2.4. android::OpenNativeLibrary()
这个函数中有条件编译，接下来我们分析的是 `ART_TARGET_ANDROID` 的编译条件分支。
跟踪 `path` 参数，可以发现它被传入到了 `android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo)` 函数中， `flag` `RTLD_NOW` 的含义是立即解析所有符号，并在加载时报告任何解析错误
- RTLD_NOW
	立即解析所有符号，并在加载时报告任何解析错误
- RTLD_LAZY
	只在符号首次使用时解析
- RTLD_GLOBAL
	将库及其符号添加到全局命名空间中，以便其他库可以使用这些符号
```cpp
// art/libnativeloader/native_loader.cpp
void* OpenNativeLibrary(JNIEnv* env, int32_t target_sdk_version, const char* path,
                        jobject class_loader, const char* caller_location, jstring library_path,
                        bool* needs_native_bridge, char** error_msg) {
#if defined(ART_TARGET_ANDROID)
  UNUSED(target_sdk_version);

  if (class_loader == nullptr) {
    *needs_native_bridge = false;
    if (caller_location != nullptr) {
      android_namespace_t* boot_namespace = FindExportedNamespace(caller_location);
      if (boot_namespace != nullptr) {
        const android_dlextinfo dlextinfo = {
            .flags = ANDROID_DLEXT_USE_NAMESPACE,
            .library_namespace = boot_namespace,
        };
        void* handle = android_dlopen_ext(path, RTLD_NOW, &dlextinfo);
        if (handle == nullptr) {
          *error_msg = strdup(dlerror());
        }
        return handle;
      }
    }

    // Check if the library is in NATIVELOADER_DEFAULT_NAMESPACE_LIBS and should
    // be loaded from the kNativeloaderExtraLibs namespace.
    {
      Result<void*> handle = TryLoadNativeloaderExtraLib(path);
      if (!handle.ok()) {
        *error_msg = strdup(handle.error().message().c_str());
        return nullptr;
      }
      if (handle.value() != nullptr) {
        return handle.value();
      }
    }

    // Fall back to the system namespace. This happens for preloaded JNI
    // libraries in the zygote.
    // TODO(b/185833744): Investigate if this should fall back to the app main
    // namespace (aka anonymous namespace) instead.
    void* handle = OpenSystemLibrary(path, RTLD_NOW);
    if (handle == nullptr) {
      *error_msg = strdup(dlerror());
    }
    return handle;
  }

  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  NativeLoaderNamespace* ns;

  if ((ns = g_namespaces->FindNamespaceByClassLoader(env, class_loader)) == nullptr) {
    // This is the case where the classloader was not created by ApplicationLoaders
    // In this case we create an isolated not-shared namespace for it.
    Result<NativeLoaderNamespace*> isolated_ns =
        CreateClassLoaderNamespaceLocked(env,
                                         target_sdk_version,
                                         class_loader,
                                         /*is_shared=*/false,
                                         /*dex_path=*/nullptr,
                                         library_path,
                                         /*permitted_path=*/nullptr,
                                         /*uses_library_list=*/nullptr);
    if (!isolated_ns.ok()) {
      *error_msg = strdup(isolated_ns.error().message().c_str());
      return nullptr;
    } else {
      ns = *isolated_ns;
    }
  }

  return OpenNativeLibraryInNamespace(ns, path, needs_native_bridge, error_msg);
}
```
### 2.5. android_dlopen_ext()
`android_dlopen_ext` 调用了 `__loader_android_dlopen_ext`
在代码的第四行出现了内建函数 `builtin_return_address(LEVEL)` , 这个函数用来返回当前函数或调用者的返回地址。函数的参数 LEVEL 表示函数调用链中的不同层次的函数，各个值代表的意义如下:

- 0：返回当前函数的返回地址； 
- 1：返回当前函数调用者的返回地址； 
- 2：返回当前函数调用者的调用者的返回地址；
```cpp
// bionic/libdl/libdl.cpp
__attribute__((__weak__))
void* android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  const void* caller_addr = __builtin_return_address(0);
  return __loader_android_dlopen_ext(filename, flag, extinfo, caller_addr);
}
```

### 2.6. __loader_android_dlopen_ext()

调用了`dlopen_ext`
```cpp
// bionic/linker/dlfcn.cpp
void* __loader_android_dlopen_ext(const char* filename,
                           int flags,
                           const android_dlextinfo* extinfo,
                           const void* caller_addr) {
  return dlopen_ext(filename, flags, extinfo, caller_addr);
}
```
### 2.7. dlopen_ext
调用了`do_dlopen`
```cpp
// bionic/linker/dlfcn.cpp
static void* dlopen_ext(const char* filename,
                        int flags,
                        const android_dlextinfo* extinfo,
                        const void* caller_addr) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  g_linker_logger.ResetState();
  void* result = do_dlopen(filename, flags, extinfo, caller_addr);
  if (result == nullptr) {
    __bionic_format_dlerror("dlopen failed", linker_get_error_buffer());
    return nullptr;
  }
  return result;
}
```
### 2.8. do_dlopen
其中`find_library`函数帮助完成so的加载
```cpp
// bionic/linker/linker.cpp
void* do_dlopen(const char* name, int flags,
                const android_dlextinfo* extinfo,
                const void* caller_addr) {
  std::string trace_prefix = std::string("dlopen: ") + (name == nullptr ? "(nullptr)" : name);
  ScopedTrace trace(trace_prefix.c_str());
  ScopedTrace loading_trace((trace_prefix + " - loading and linking").c_str());
  soinfo* const caller = find_containing_library(caller_addr);
  android_namespace_t* ns = get_caller_namespace(caller);

  LD_LOG(kLogDlopen,
         "dlopen(name=\"%s\", flags=0x%x, extinfo=%s, caller=\"%s\", caller_ns=%s@%p, targetSdkVersion=%i) ...",
         name,
         flags,
         android_dlextinfo_to_string(extinfo).c_str(),
         caller == nullptr ? "(null)" : caller->get_realpath(),
         ns == nullptr ? "(null)" : ns->get_name(),
         ns,
         get_application_target_sdk_version());

  auto purge_guard = android::base::make_scope_guard([&]() { purge_unused_memory(); });

  auto failure_guard = android::base::make_scope_guard(
      [&]() { LD_LOG(kLogDlopen, "... dlopen failed: %s", linker_get_error_buffer()); });

  if ((flags & ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL|RTLD_NODELETE|RTLD_NOLOAD)) != 0) {
    DL_OPEN_ERR("invalid flags to dlopen: %x", flags);
    return nullptr;
  }

  if (extinfo != nullptr) {
    if ((extinfo->flags & ~(ANDROID_DLEXT_VALID_FLAG_BITS)) != 0) {
      DL_OPEN_ERR("invalid extended flags to android_dlopen_ext: 0x%" PRIx64, extinfo->flags);
      return nullptr;
    }

    if ((extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD) == 0 &&
        (extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET) != 0) {
      DL_OPEN_ERR("invalid extended flag combination (ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET without "
          "ANDROID_DLEXT_USE_LIBRARY_FD): 0x%" PRIx64, extinfo->flags);
      return nullptr;
    }

    if ((extinfo->flags & ANDROID_DLEXT_USE_NAMESPACE) != 0) {
      if (extinfo->library_namespace == nullptr) {
        DL_OPEN_ERR("ANDROID_DLEXT_USE_NAMESPACE is set but extinfo->library_namespace is null");
        return nullptr;
      }
      ns = extinfo->library_namespace;
    }
  }

  // Workaround for dlopen(/system/lib/<soname>) when .so is in /apex. http://b/121248172
  // The workaround works only when targetSdkVersion < Q.
  std::string name_to_apex;
  if (translateSystemPathToApexPath(name, &name_to_apex)) {
    const char* new_name = name_to_apex.c_str();
    LD_LOG(kLogDlopen, "dlopen considering translation from %s to APEX path %s",
           name,
           new_name);
    // Some APEXs could be optionally disabled. Only translate the path
    // when the old file is absent and the new file exists.
    // TODO(b/124218500): Re-enable it once app compat issue is resolved
    /*
    if (file_exists(name)) {
      LD_LOG(kLogDlopen, "dlopen %s exists, not translating", name);
    } else
    */
    if (!file_exists(new_name)) {
      LD_LOG(kLogDlopen, "dlopen %s does not exist, not translating",
             new_name);
    } else {
      LD_LOG(kLogDlopen, "dlopen translation accepted: using %s", new_name);
      name = new_name;
    }
  }
  // End Workaround for dlopen(/system/lib/<soname>) when .so is in /apex.

  std::string asan_name_holder;

  const char* translated_name = name;
  if (g_is_asan && translated_name != nullptr && translated_name[0] == '/') {
    char original_path[PATH_MAX];
    if (realpath(name, original_path) != nullptr) {
      asan_name_holder = std::string(kAsanLibDirPrefix) + original_path;
      if (file_exists(asan_name_holder.c_str())) {
        soinfo* si = nullptr;
        if (find_loaded_library_by_realpath(ns, original_path, true, &si)) {
          PRINT("linker_asan dlopen NOT translating \"%s\" -> \"%s\": library already loaded", name,
                asan_name_holder.c_str());
        } else {
          PRINT("linker_asan dlopen translating \"%s\" -> \"%s\"", name, translated_name);
          translated_name = asan_name_holder.c_str();
        }
      }
    }
  }

  ProtectedDataGuard guard;
  soinfo* si = find_library(ns, translated_name, flags, extinfo, caller);
  loading_trace.End();

  if (si != nullptr) {
    void* handle = si->to_handle();
    LD_LOG(kLogDlopen,
           "... dlopen calling constructors: realpath=\"%s\", soname=\"%s\", handle=%p",
           si->get_realpath(), si->get_soname(), handle);
    si->call_constructors();
    failure_guard.Disable();
    LD_LOG(kLogDlopen,
           "... dlopen successful: realpath=\"%s\", soname=\"%s\", handle=%p",
           si->get_realpath(), si->get_soname(), handle);
    return handle;
  }

  return nullptr;
}
```

#### 2.8.1. call_constructors
```cpp
// bionic/linker/linker_soinfo.cpp
void soinfo::call_constructors() {
  if (constructors_called || g_is_ldd) {
    return;
  }

  // We set constructors_called before actually calling the constructors, otherwise it doesn't
  // protect against recursive constructor calls. One simple example of constructor recursion
  // is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
  // 1. The program depends on libc, so libc's constructor is called here.
  // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
  // 3. dlopen() calls the constructors on the newly created
  //    soinfo for libc_malloc_debug_leak.so.
  // 4. The debug .so depends on libc, so CallConstructors is
  //    called again with the libc soinfo. If it doesn't trigger the early-
  //    out above, the libc constructor will be called again (recursively!).
  constructors_called = true;

  if (!is_main_executable() && preinit_array_ != nullptr) {
    // The GNU dynamic linker silently ignores these, but we warn the developer.
    PRINT("\"%s\": ignoring DT_PREINIT_ARRAY in shared library!", get_realpath());
  }

  get_children().for_each([] (soinfo* si) {
    si->call_constructors();
  });

  if (!is_linker()) {
    bionic_trace_begin((std::string("calling constructors: ") + get_realpath()).c_str());
  }

  // DT_INIT should be called before DT_INIT_ARRAY if both are present.
  call_function("DT_INIT", init_func_, get_realpath());
  call_array("DT_INIT_ARRAY", init_array_, init_array_count_, false, get_realpath());

  if (!is_linker()) {
    bionic_trace_end();
  }
}
```
在一个so文件中，`.preinit_array`，`.init_array`，`.init`和`JNI_OnLoad`的执行顺序就是 `.preinit_array`，`.init`，`.init_array`，`JNI_OnLoad`。但是由于前面提到，在so中`.preinit_array`会被忽略，所以真正的执行顺序是`.init`，`.init_array`，`JNI_OnLoad`。

### 2.9. find_library
调用了`find_libraries`

```cpp
// bionic/linker/linker.cpp
static soinfo* find_library(android_namespace_t* ns,
                            const char* name, int rtld_flags,
                            const android_dlextinfo* extinfo,
                            soinfo* needed_by) {
  soinfo* si = nullptr;

  if (name == nullptr) {
    si = solist_get_somain();
  } else if (!find_libraries(ns,
                             needed_by,
                             &name,
                             1,
                             &si,
                             nullptr,
                             0,
                             rtld_flags,
                             extinfo,
                             false /* add_as_children */)) {
    if (si != nullptr) {
      soinfo_unload(si);
    }
    return nullptr;
  }

  si->increment_ref_count();

  return si;
}
```
### 2.10. find_libraries
```cpp
// bionic/linker/linker.cpp
bool find_libraries(android_namespace_t* ns,
                    soinfo* start_with,
                    const char* const library_names[],
                    size_t library_names_count,
                    soinfo* soinfos[],
                    std::vector<soinfo*>* ld_preloads,
                    size_t ld_preloads_count,
                    int rtld_flags,
                    const android_dlextinfo* extinfo,
                    bool add_as_children,
                    std::vector<android_namespace_t*>* namespaces)
```
该函数可按照注释分为`step0 - step7`八个步骤
#### 2.10.1. Step 0: 准备工作
**初始化数据结构**：
- `readers_map`：一个映射表，用于存储 soinfo 和对应的 `ElfReader`（用于解析 ELF 文件）。
- `load_tasks`：一个任务列表，用于管理所有需要加载的库。将待加载的 so 添加到 `LoadTaskList` 加载任务队列中
这一步为后续加载和链接做好准备，确保任务和输出数组就绪。
```cpp
// bionic/linker/linker.cpp
// Step 0: prepare.
  std::unordered_map<const soinfo*, ElfReader> readers_map;
  LoadTaskList load_tasks;

  for (size_t i = 0; i < library_names_count; ++i) {
    const char* name = library_names[i];
    load_tasks.push_back(LoadTask::create(name, start_with, ns, &readers_map));
  }

  // If soinfos array is null allocate one on stack.
  // The array is needed in case of failure; for example
  // when library_names[] = {libone.so, libtwo.so} and libone.so
  // is loaded correctly but libtwo.so failed for some reason.
  // In this case libone.so should be unloaded on return.
  // See also implementation of failure_guard below.

  if (soinfos == nullptr) {
    size_t soinfos_size = sizeof(soinfo*)*library_names_count;
    soinfos = reinterpret_cast<soinfo**>(alloca(soinfos_size));
    memset(soinfos, 0, soinfos_size);
  }

  // list of libraries to link - see step 2.
  size_t soinfos_count = 0;

  auto scope_guard = android::base::make_scope_guard([&]() {
    for (LoadTask* t : load_tasks) {
      LoadTask::deleter(t);
    }
  });

  ZipArchiveCache zip_archive_cache;
  soinfo_list_t new_global_group_members;
```


#### 2.10.2. Step 1: 扩展加载任务列表
遍历 `load_tasks`，查找每个库并并将so库依赖（`DT_NEEDED`）的其他库也加入到load_tasks加载任务队列中。调用`find_library_internal` 查找库并更新 `load_tasks`（此时不加载，只解析依赖）。这一步确保所有相关库（包括依赖）都被识别并记录，**但尚未加载到内存!**
```cpp
// bionic/linker/linker.cpp
// Step 1: expand the list of load_tasks to include
  // all DT_NEEDED libraries (do not load them just yet)
  for (size_t i = 0; i<load_tasks.size(); ++i) {
    LoadTask* task = load_tasks[i];
    soinfo* needed_by = task->get_needed_by();

    bool is_dt_needed = needed_by != nullptr && (needed_by != start_with || add_as_children);
    task->set_extinfo(is_dt_needed ? nullptr : extinfo);
    task->set_dt_needed(is_dt_needed);

    LD_LOG(kLogDlopen, "find_libraries(ns=%s): task=%s, is_dt_needed=%d", ns->get_name(),
           task->get_name(), is_dt_needed);

    // Note: start from the namespace that is stored in the LoadTask. This namespace
    // is different from the current namespace when the LoadTask is for a transitive
    // dependency and the lib that created the LoadTask is not found in the
    // current namespace but in one of the linked namespace.
    if (!find_library_internal(const_cast<android_namespace_t*>(task->get_start_from()),
                               task,
                               &zip_archive_cache,
                               &load_tasks,
                               rtld_flags)) {
      return false;
    }

    soinfo* si = task->get_soinfo();

    if (is_dt_needed) {
      needed_by->add_child(si);
    }

    // When ld_preloads is not null, the first
    // ld_preloads_count libs are in fact ld_preloads.
    bool is_ld_preload = false;
    if (ld_preloads != nullptr && soinfos_count < ld_preloads_count) {
      ld_preloads->push_back(si);
      is_ld_preload = true;
    }

    if (soinfos_count < library_names_count) {
      soinfos[soinfos_count++] = si;
    }

    // Add the new global group members to all initial namespaces. Do this secondary namespace setup
    // at the same time that libraries are added to their primary namespace so that the order of
    // global group members is the same in the every namespace. Only add a library to a namespace
    // once, even if it appears multiple times in the dependency graph.
    if (is_ld_preload || (si->get_dt_flags_1() & DF_1_GLOBAL) != 0) {
      if (!si->is_linked() && namespaces != nullptr && !new_global_group_members.contains(si)) {
        new_global_group_members.push_back(si);
        for (auto linked_ns : *namespaces) {
          if (si->get_primary_namespace() != linked_ns) {
            linked_ns->add_soinfo(si);
            si->add_secondary_namespace(linked_ns);
          }
        }
      }
    }
  }
```

##### 2.10.2.1. find_library_internal
主要做了以下四步
- 调用 `find_loaded_library_by_soname`，根据库的 soname（共享对象名称）在当前命名空间及其链接的命名空间中查找有没有加载过，如果找到就设置 `task` 的 `soinfo` 为找到的库并且返回。

- 如果上一步没有找到，就使用更精确的 `load_library` 函数查找。**再次强调，虽然函数名称叫 `load_library` ，但是它不负责将文件内容映射到内存 (mmap)。 实际的内存映射是在 `find_libraries` 的 Step 2 中由 task->load() 完成的。** 这一步是加载库的主要尝试，负责解析库文件并处理其依赖关系。

- 为特定的系统库提供特殊处理，允许它们从默认命名空间加载。检查当前命名空间是否启用了豁免列表（`is_exempt_list_enabled()`）。检查目标库是否在豁免列表中（`is_exempt_lib()`）。如果满足条件，切换到全局默认命名空间（`g_default_namespace`），然后再次调用 `load_library`。

- 如果前面的尝试都失败，遍历当前命名空间的链接命名空间，尝试查找或加载库。遍历 `ns->linked_namespaces()` 中的每个链接命名空间。对每个命名空间调用 `find_library_in_linked_namespace` 检查库是否已加载。


```cpp
// bionic/linker/linker.cpp
static bool find_library_internal(android_namespace_t* ns,
                                  LoadTask* task,
                                  ZipArchiveCache* zip_archive_cache,
                                  LoadTaskList* load_tasks,
                                  int rtld_flags) {
  soinfo* candidate;

  if (find_loaded_library_by_soname(ns, task->get_name(), true /* search_linked_namespaces */,
                                    &candidate)) {
    LD_LOG(kLogDlopen,
           "find_library_internal(ns=%s, task=%s): Already loaded (by soname): %s",
           ns->get_name(), task->get_name(), candidate->get_realpath());
    task->set_soinfo(candidate);
    return true;
  }

  // Library might still be loaded, the accurate detection
  // of this fact is done by load_library.
  TRACE("[ \"%s\" find_loaded_library_by_soname failed (*candidate=%s@%p). Trying harder... ]",
        task->get_name(), candidate == nullptr ? "n/a" : candidate->get_realpath(), candidate);

  if (load_library(ns, task, zip_archive_cache, load_tasks, rtld_flags,
                   true /* search_linked_namespaces */)) {
    return true;
  }

  // TODO(dimitry): workaround for http://b/26394120 (the exempt-list)
  if (ns->is_exempt_list_enabled() && is_exempt_lib(ns, task->get_name(), task->get_needed_by())) {
    // For the libs in the exempt-list, switch to the default namespace and then
    // try the load again from there. The library could be loaded from the
    // default namespace or from another namespace (e.g. runtime) that is linked
    // from the default namespace.
    LD_LOG(kLogDlopen,
           "find_library_internal(ns=%s, task=%s): Exempt system library - trying namespace %s",
           ns->get_name(), task->get_name(), g_default_namespace.get_name());
    ns = &g_default_namespace;
    if (load_library(ns, task, zip_archive_cache, load_tasks, rtld_flags,
                     true /* search_linked_namespaces */)) {
      return true;
    }
  }
  // END OF WORKAROUND

  // if a library was not found - look into linked namespaces
  // preserve current dlerror in the case it fails.
  DlErrorRestorer dlerror_restorer;
  LD_LOG(kLogDlopen, "find_library_internal(ns=%s, task=%s): Trying %zu linked namespaces",
         ns->get_name(), task->get_name(), ns->linked_namespaces().size());
  for (auto& linked_namespace : ns->linked_namespaces()) {
    if (find_library_in_linked_namespace(linked_namespace, task)) {
      // Library is already loaded.
      if (task->get_soinfo() != nullptr) {
        // n.b. This code path runs when find_library_in_linked_namespace found an already-loaded
        // library by soname. That should only be possible with a exempt-list lookup, where we
        // switch the namespace, because otherwise, find_library_in_linked_namespace is duplicating
        // the soname scan done in this function's first call to find_loaded_library_by_soname.
        return true;
      }

      if (load_library(linked_namespace.linked_namespace(), task, zip_archive_cache, load_tasks,
                       rtld_flags, false /* search_linked_namespaces */)) {
        LD_LOG(kLogDlopen, "find_library_internal(ns=%s, task=%s): Found in linked namespace %s",
               ns->get_name(), task->get_name(), linked_namespace.linked_namespace()->get_name());
        return true;
      }
    }
  }

  return false;
}
```
既然如此，那么我们的so应该走`load_library`
##### 2.10.2.2. load_library
在这个函数中，首先判断 `extinfo->flags` 是否是 `ANDROID_DLEXT_USE_LIBRARY_FD` , 如果同时有 `ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET` , 标志在 [Android 官网的解释](https://developer.android.com/ndk/reference/group/libdl "Android 官网的解释")如下
![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/20250501161743824.png)
那这样就方便了，假如已经有了这个 library 的 `fd` 文件描述符，那直接拿过来用就可以了

但是我们待加载的 so 的 `extinfo->flags` 已经在 `android::OpenNativeLibrary` 中被定义为 `ANDROID_DLEXT_USE_NAMESPACE` 了，这个标志的含义在上图中也有给出，所以很遗憾，这个 `if` 语句中的代码并不会被执行
![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/20250501161835881.png)
那么为什么要特意在此处加入这个 if 语句呢？ [作者](https://oacia.dev/android-load-so/)的理解是为了提高运行的效率，有一些底层的库已经打开过，加载过了，那么就完全没有必要再打开，搜索一次，直接把 library 的 fd 文件描述符拿过来用就可以了

不会走第一个if 语句，那么就是调用了`open_library`

```cpp
// bionic/linker/linker.cpp
static bool load_library(android_namespace_t* ns,
                         LoadTask* task,
                         ZipArchiveCache* zip_archive_cache,
                         LoadTaskList* load_tasks,
                         int rtld_flags,
                         bool search_linked_namespaces) {
  const char* name = task->get_name();
  soinfo* needed_by = task->get_needed_by();
  const android_dlextinfo* extinfo = task->get_extinfo();

  if (extinfo != nullptr && (extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD) != 0) {
    off64_t file_offset = 0;
    if ((extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET) != 0) {
      file_offset = extinfo->library_fd_offset;
    }

    std::string realpath;
    if (!realpath_fd(extinfo->library_fd, &realpath)) {
      if (!is_first_stage_init()) {
        PRINT(
            "warning: unable to get realpath for the library \"%s\" by extinfo->library_fd. "
            "Will use given name.",
            name);
      }
      realpath = name;
    }

    task->set_fd(extinfo->library_fd, false);
    task->set_file_offset(file_offset);
    return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
  }

  LD_LOG(kLogDlopen,
         "load_library(ns=%s, task=%s, flags=0x%x, search_linked_namespaces=%d): calling "
         "open_library",
         ns->get_name(), name, rtld_flags, search_linked_namespaces);

  // Open the file.
  off64_t file_offset;
  std::string realpath;
  int fd = open_library(ns, zip_archive_cache, name, needed_by, &file_offset, &realpath);
  if (fd == -1) {
    if (task->is_dt_needed()) {
      if (needed_by->is_main_executable()) {
        DL_OPEN_ERR("library \"%s\" not found: needed by main executable", name);
      } else {
        DL_OPEN_ERR("library \"%s\" not found: needed by %s in namespace %s", name,
                    needed_by->get_realpath(), task->get_start_from()->get_name());
      }
    } else {
      DL_OPEN_ERR("library \"%s\" not found", name);
    }
    return false;
  }

  task->set_fd(fd, true);
  task->set_file_offset(file_offset);

  return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
}
```
##### 2.10.2.3. open_library()
分析传入的是绝对路径的so，那么进入第一个 if 语句，即 `open_library_at_path` 。
```cpp
// bionic/linker/linker.cpp
static int open_library(android_namespace_t* ns,
                        ZipArchiveCache* zip_archive_cache,
                        const char* name, soinfo *needed_by,
                        off64_t* file_offset, std::string* realpath) {
  TRACE("[ opening %s from namespace %s ]", name, ns->get_name());

  // If the name contains a slash, we should attempt to open it directly and not search the paths.
  if (strchr(name, '/') != nullptr) {
    return open_library_at_path(zip_archive_cache, name, file_offset, realpath);
  }

  // LD_LIBRARY_PATH has the highest priority. We don't have to check accessibility when searching
  // the namespace's path lists, because anything found on a namespace path list should always be
  // accessible.
  int fd = open_library_on_paths(zip_archive_cache, name, file_offset, ns->get_ld_library_paths(), realpath);

  // Try the DT_RUNPATH, and verify that the library is accessible.
  if (fd == -1 && needed_by != nullptr) {
    fd = open_library_on_paths(zip_archive_cache, name, file_offset, needed_by->get_dt_runpath(), realpath);
    if (fd != -1 && !ns->is_accessible(*realpath)) {
      close(fd);
      fd = -1;
    }
  }

  // Finally search the namespace's main search path list.
  if (fd == -1) {
    fd = open_library_on_paths(zip_archive_cache, name, file_offset, ns->get_default_library_paths(), realpath);
  }

  return fd;
}
```

##### 2.10.2.4. open_library_at_path
在第二个 if 语句中使用`open`打开了so，并且返回了fd，那么返回到 `load_library` 看看使用fd做了什么操作。

进入到了另一个重载函数里
```cpp
return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
```

```cpp
// bionic/linker/linker.cpp
static int open_library_at_path(ZipArchiveCache* zip_archive_cache,
                                const char* path, off64_t* file_offset,
                                std::string* realpath) {
  int fd = -1;
  // 如果路径中包含 "!/", 则通过 zipfile 打开库
  if (strstr(path, kZipFileSeparator) != nullptr) {
    fd = open_library_in_zipfile(zip_archive_cache, path, file_offset, realpath);
  }

  if (fd == -1) {
    fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
    if (fd != -1) {
      *file_offset = 0;
      if (!realpath_fd(fd, realpath)) {
        if (!is_first_stage_init()) {
          PRINT("warning: unable to get realpath for the library \"%s\". Will use given path.",
                path);
        }
        *realpath = path;
      }
    }
  }

  return fd;
}
```
##### 2.10.2.5. 重载的load_library
前面是一堆的合法性检查，直到 `task->read(realpath.c_str(), file_stat.st_size)` 开始解析so
```cpp
// bionic/linker/linker.cpp
static bool load_library(android_namespace_t* ns,
                         LoadTask* task,
                         LoadTaskList* load_tasks,
                         int rtld_flags,
                         const std::string& realpath,
                         bool search_linked_namespaces) {
  off64_t file_offset = task->get_file_offset();
  const char* name = task->get_name();
  const android_dlextinfo* extinfo = task->get_extinfo();

  LD_LOG(kLogDlopen,
         "load_library(ns=%s, task=%s, flags=0x%x, realpath=%s, search_linked_namespaces=%d)",
         ns->get_name(), name, rtld_flags, realpath.c_str(), search_linked_namespaces);

  if ((file_offset % PAGE_SIZE) != 0) {
    DL_OPEN_ERR("file offset for the library \"%s\" is not page-aligned: %" PRId64, name, file_offset);
    return false;
  }
  if (file_offset < 0) {
    DL_OPEN_ERR("file offset for the library \"%s\" is negative: %" PRId64, name, file_offset);
    return false;
  }

  struct stat file_stat;
  if (TEMP_FAILURE_RETRY(fstat(task->get_fd(), &file_stat)) != 0) {
    DL_OPEN_ERR("unable to stat file for the library \"%s\": %s", name, strerror(errno));
    return false;
  }
  if (file_offset >= file_stat.st_size) {
    DL_OPEN_ERR("file offset for the library \"%s\" >= file size: %" PRId64 " >= %" PRId64,
        name, file_offset, file_stat.st_size);
    return false;
  }

  // Check for symlink and other situations where
  // file can have different names, unless ANDROID_DLEXT_FORCE_LOAD is set
  if (extinfo == nullptr || (extinfo->flags & ANDROID_DLEXT_FORCE_LOAD) == 0) {
    soinfo* si = nullptr;
    if (find_loaded_library_by_inode(ns, file_stat, file_offset, search_linked_namespaces, &si)) {
      LD_LOG(kLogDlopen,
             "load_library(ns=%s, task=%s): Already loaded under different name/path \"%s\" - "
             "will return existing soinfo",
             ns->get_name(), name, si->get_realpath());
      task->set_soinfo(si);
      return true;
    }
  }

  if ((rtld_flags & RTLD_NOLOAD) != 0) {
    DL_OPEN_ERR("library \"%s\" wasn't loaded and RTLD_NOLOAD prevented it", name);
    return false;
  }

  struct statfs fs_stat;
  if (TEMP_FAILURE_RETRY(fstatfs(task->get_fd(), &fs_stat)) != 0) {
    DL_OPEN_ERR("unable to fstatfs file for the library \"%s\": %s", name, strerror(errno));
    return false;
  }

  // do not check accessibility using realpath if fd is located on tmpfs
  // this enables use of memfd_create() for apps
  if ((fs_stat.f_type != TMPFS_MAGIC) && (!ns->is_accessible(realpath))) {
    // TODO(dimitry): workaround for http://b/26394120 - the exempt-list

    // TODO(dimitry) before O release: add a namespace attribute to have this enabled
    // only for classloader-namespaces
    const soinfo* needed_by = task->is_dt_needed() ? task->get_needed_by() : nullptr;
    if (is_exempt_lib(ns, name, needed_by)) {
      // print warning only if needed by non-system library
      if (needed_by == nullptr || !is_system_library(needed_by->get_realpath())) {
        const soinfo* needed_or_dlopened_by = task->get_needed_by();
        const char* sopath = needed_or_dlopened_by == nullptr ? "(unknown)" :
                                                      needed_or_dlopened_by->get_realpath();
        DL_WARN_documented_change(24,
                                  "private-api-enforced-for-api-level-24",
                                  "library \"%s\" (\"%s\") needed or dlopened by \"%s\" "
                                  "is not accessible by namespace \"%s\"",
                                  name, realpath.c_str(), sopath, ns->get_name());
        add_dlwarning(sopath, "unauthorized access to",  name);
      }
    } else {
      // do not load libraries if they are not accessible for the specified namespace.
      const char* needed_or_dlopened_by = task->get_needed_by() == nullptr ?
                                          "(unknown)" :
                                          task->get_needed_by()->get_realpath();

      DL_OPEN_ERR("library \"%s\" needed or dlopened by \"%s\" is not accessible for the namespace \"%s\"",
             name, needed_or_dlopened_by, ns->get_name());

      // do not print this if a library is in the list of shared libraries for linked namespaces
      if (!maybe_accessible_via_namespace_links(ns, name)) {
        PRINT("library \"%s\" (\"%s\") needed or dlopened by \"%s\" is not accessible for the"
              " namespace: [name=\"%s\", ld_library_paths=\"%s\", default_library_paths=\"%s\","
              " permitted_paths=\"%s\"]",
              name, realpath.c_str(),
              needed_or_dlopened_by,
              ns->get_name(),
              android::base::Join(ns->get_ld_library_paths(), ':').c_str(),
              android::base::Join(ns->get_default_library_paths(), ':').c_str(),
              android::base::Join(ns->get_permitted_paths(), ':').c_str());
      }
      return false;
    }
  }

  soinfo* si = soinfo_alloc(ns, realpath.c_str(), &file_stat, file_offset, rtld_flags);

  task->set_soinfo(si);

  // Read the ELF header and some of the segments.
  if (!task->read(realpath.c_str(), file_stat.st_size)) {
    task->remove_cached_elf_reader();
    task->set_soinfo(nullptr);
    soinfo_free(si);
    return false;
  }

  // Find and set DT_RUNPATH, DT_SONAME, and DT_FLAGS_1.
  // Note that these field values are temporary and are
  // going to be overwritten on soinfo::prelink_image
  // with values from PT_LOAD segments.
  const ElfReader& elf_reader = task->get_elf_reader();
  for (const ElfW(Dyn)* d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_RUNPATH) {
      si->set_dt_runpath(elf_reader.get_string(d->d_un.d_val));
    }
    if (d->d_tag == DT_SONAME) {
      si->set_soname(elf_reader.get_string(d->d_un.d_val));
    }
    // We need to identify a DF_1_GLOBAL library early so we can link it to namespaces.
    if (d->d_tag == DT_FLAGS_1) {
      si->set_dt_flags_1(d->d_un.d_val);
    }
  }

#if !defined(__ANDROID__)
  // Bionic on the host currently uses some Android prebuilts, which don't set
  // DT_RUNPATH with any relative paths, so they can't find their dependencies.
  // b/118058804
  if (si->get_dt_runpath().empty()) {
    si->set_dt_runpath("$ORIGIN/../lib64:$ORIGIN/lib64");
  }
#endif

  for_each_dt_needed(task->get_elf_reader(), [&](const char* name) {
    LD_LOG(kLogDlopen, "load_library(ns=%s, task=%s): Adding DT_NEEDED task: %s",
           ns->get_name(), task->get_name(), name);
    load_tasks->push_back(LoadTask::create(name, si, ns, task->get_readers_map()));
  });

  return true;
}
```
##### 2.10.2.6. read
```cpp
// bionic/linker/linker.cpp
bool read(const char* realpath, off64_t file_size) {
    ElfReader& elf_reader = get_elf_reader();
    return elf_reader.Read(realpath, fd_, file_offset_, file_size);
  }
```

在获取到待加载的 so 的各个段的结构之后，接下来就是解析 `.dynamic` 中保存的符号
##### 2.10.2.7. ElfReader::Read

```cpp
// bionic/linker/linker_phdr.cpp
bool ElfReader::Read(const char* name, int fd, off64_t file_offset, off64_t file_size) {
  if (did_read_) {
    return true;
  }
  name_ = name;
  fd_ = fd;
  file_offset_ = file_offset;
  file_size_ = file_size;

  if (ReadElfHeader() && // 从文件中读取 ELF 头部信息
      VerifyElfHeader() && // 验证 ELF 头的有效性，比如检查魔数（magic number）、字节序和架构是否正确。
      ReadProgramHeaders() && // 读取程序头表，描述 ELF 文件的段（segments）。
      ReadSectionHeaders() && // 读取节头表，描述 ELF 文件的节（sections）。
      ReadDynamicSection()) { // 读取动态节（.dynamic 节），包含动态链接相关的信息。
    did_read_ = true;
  }

  return did_read_;
}
```
在获取到待加载的 so 的各个段的结构之后，接下来就是解析 `.dynamic` 中保存的符号
```cpp
// bionic/linker/linker.cpp
// Find and set DT_RUNPATH, DT_SONAME, and DT_FLAGS_1.
// Note that these field values are temporary and are
// going to be overwritten on soinfo::prelink_image
// with values from PT_LOAD segments.
const ElfReader& elf_reader = task->get_elf_reader();
for (const ElfW(Dyn)* d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_RUNPATH) {
        si->set_dt_runpath(elf_reader.get_string(d->d_un.d_val));
    }
    if (d->d_tag == DT_SONAME) {
        si->set_soname(elf_reader.get_string(d->d_un.d_val));
    }
    // We need to identify a DF_1_GLOBAL library early so we can link it to namespaces.
    if (d->d_tag == DT_FLAGS_1) {
        si->set_dt_flags_1(d->d_un.d_val);
    }
}
```
之后找到待加载的 so 的依赖库，这里有一个模板函数 `for_each_dt_needed` , 找到 `.dynamic` 中所有带有 `DT_NEEDED` 标志的字符串，这些字符串的名称就是这个 so 所需要的依赖库，然后将它们添加到 `load_tasks` 队列中
```cpp
// bionic/linker/linker.cpp
for_each_dt_needed(task->get_elf_reader(), [&](const char* name) {
    LD_LOG(kLogDlopen, "load_library(ns=%s, task=%s): Adding DT_NEEDED task: %s",
           ns->get_name(), task->get_name(), name);
    load_tasks->push_back(LoadTask::create(name, si, ns, task->get_readers_map()));
});

//android-platform\bionic\linker\linker_soinfo.h
template<typename F>
void for_each_dt_needed(const soinfo* si, F action) {
  for (const ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_NEEDED) {
      action(fix_dt_needed(si->get_string(d->d_un.d_val), si->get_realpath()));
    }
  }
}
```
#### 2.10.3. Step 2: 加载库
将所有未链接的库加载到内存中。遍历 `load_list`，调用 `task->load` 将库加载到内存。这一步完成库的实际加载，将 ELF 文件映射到进程的地址空间。

```cpp
// bionic/linker/linker.cpp
// Step 2: Load libraries in random order (see b/24047022)
  LoadTaskList load_list;
  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    auto pred = [&](const LoadTask* t) {
      return t->get_soinfo() == si;
    };

    if (!si->is_linked() &&
        std::find_if(load_list.begin(), load_list.end(), pred) == load_list.end() ) {
      load_list.push_back(task);
    }
  }
  bool reserved_address_recursive = false;
  if (extinfo) {
    reserved_address_recursive = extinfo->flags & ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE;
  }
  if (!reserved_address_recursive) {
    // Shuffle the load order in the normal case, but not if we are loading all
    // the libraries to a reserved address range.
    shuffle(&load_list);
  }

  // Set up address space parameters.
  address_space_params extinfo_params, default_params;
  size_t relro_fd_offset = 0;
  if (extinfo) {
    if (extinfo->flags & ANDROID_DLEXT_RESERVED_ADDRESS) {
      extinfo_params.start_addr = extinfo->reserved_addr;
      extinfo_params.reserved_size = extinfo->reserved_size;
      extinfo_params.must_use_address = true;
    } else if (extinfo->flags & ANDROID_DLEXT_RESERVED_ADDRESS_HINT) {
      extinfo_params.start_addr = extinfo->reserved_addr;
      extinfo_params.reserved_size = extinfo->reserved_size;
    }
  }

  for (auto&& task : load_list) {
    address_space_params* address_space =
        (reserved_address_recursive || !task->is_dt_needed()) ? &extinfo_params : &default_params;
    if (!task->load(address_space)) {
      return false;
    }
  }
```


```cpp
// bionic/linker/linker.cpp
  bool load(address_space_params* address_space) {
    ElfReader& elf_reader = get_elf_reader();
    if (!elf_reader.Load(address_space)) {
      return false;
    }

    si_->base = elf_reader.load_start();
    si_->size = elf_reader.load_size();
    si_->set_mapped_by_caller(elf_reader.is_mapped_by_caller());
    si_->load_bias = elf_reader.load_bias();
    si_->phnum = elf_reader.phdr_count();
    si_->phdr = elf_reader.loaded_phdr();
    si_->set_gap_start(elf_reader.gap_start());
    si_->set_gap_size(elf_reader.gap_size());

    return true;
  }
```

- `ElfReader::Load()`调用`LoadSegments()`，`LoadSegments()`中调用`mmap`将so文件的`PT_LOAD`段都map到加载基地址`load_bias_`中
- `ElfReader::Load()`调用`phdr_table_protect_segments()`，`phdr_table_protect_segments()`中调用mprotect修改各个PT_LOAD程序段的内存属性
#### 2.10.4. Step 3: 预链接依赖库
对所有未链接的库进行预链接（解析 ELF 文件头和程序段），调用 `prelink_image` 解析库的程序头（`phdr`）和其他元数据。确保库的内存布局正确，为后续符号链接做准备。
```cpp
// bionic/linker/linker.cpp
  // Step 3: pre-link all DT_NEEDED libraries in breadth first order.
for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    if (!si->is_linked() && !si->prelink_image()) {
      return false;
    }
    register_soinfo_tls(si);
}
```
#### 2.10.5. Step 4: 构建全局组
为所有预加载库设置 `DF_1_GLOBAL` 标志，确保它们对所有命名空间可见。保证预加载库（如 `LD_PRELOAD`）在全局范围内可用。
```cpp
// Step 4: Construct the global group. DF_1_GLOBAL bit is force set for LD_PRELOADed libs because
  // they must be added to the global group. Note: The DF_1_GLOBAL bit for a library is normally set
  // in step 3.
  if (ld_preloads != nullptr) {
    for (auto&& si : *ld_preloads) {
      si->set_dt_flags_1(si->get_dt_flags_1() | DF_1_GLOBAL);
    }
  }
```

这里我们看到调用了 `prelink_image` 来预链接依赖库，主要是遍历 `.dynamic` 节，来提取必要的信息例如 `strtab_` , `symtab_` , `plt_rela_` , `init_array_` 等等各种必要的信息
```cpp
// bionic/linker/linker.cpp
bool soinfo::prelink_image() {
  if (flags_ & FLAG_PRELINKED) return true;
  /* Extract dynamic section */
  ElfW(Word) dynamic_flags = 0;
  phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);

  /* We can't log anything until the linker is relocated */
  bool relocating_linker = (flags_ & FLAG_LINKER) != 0;
  if (!relocating_linker) {
    INFO("[ Linking \"%s\" ]", get_realpath());
    DEBUG("si->base = %p si->flags = 0x%08x", reinterpret_cast<void*>(base), flags_);
  }

  if (dynamic == nullptr) {
    if (!relocating_linker) {
      DL_ERR("missing PT_DYNAMIC in \"%s\"", get_realpath());
    }
    return false;
  } else {
    if (!relocating_linker) {
      DEBUG("dynamic = %p", dynamic);
    }
  }

#if defined(__arm__)
  (void) phdr_table_get_arm_exidx(phdr, phnum, load_bias,
                                  &ARM_exidx, &ARM_exidx_count);
#endif

  TlsSegment tls_segment;
  if (__bionic_get_tls_segment(phdr, phnum, load_bias, &tls_segment)) {
    if (!__bionic_check_tls_alignment(&tls_segment.alignment)) {
      if (!relocating_linker) {
        DL_ERR("TLS segment alignment in \"%s\" is not a power of 2: %zu",
               get_realpath(), tls_segment.alignment);
      }
      return false;
    }
    tls_ = std::make_unique<soinfo_tls>();
    tls_->segment = tls_segment;
  }

  // Extract useful information from dynamic section.
  // Note that: "Except for the DT_NULL element at the end of the array,
  // and the relative order of DT_NEEDED elements, entries may appear in any order."
  //
  // source: http://www.sco.com/developers/gabi/1998-04-29/ch5.dynamic.html
  uint32_t needed_count = 0;
  for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
    DEBUG("d = %p, d[0](tag) = %p d[1](val) = %p",
          d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
    switch (d->d_tag) {
      case DT_SONAME:
        // this is parsed after we have strtab initialized (see below).
        break;
		// 哈希表
      case DT_HASH:
        nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        nchain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
        bucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
        chain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + nbucket_ * 4);
        break;

      case DT_GNU_HASH:
        gnu_nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        // skip symndx
        gnu_maskwords_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[2];
        gnu_shift2_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[3];

        gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr)*>(load_bias + d->d_un.d_ptr + 16);
        gnu_bucket_ = reinterpret_cast<uint32_t*>(gnu_bloom_filter_ + gnu_maskwords_);
        // amend chain for symndx = header[1]
        gnu_chain_ = gnu_bucket_ + gnu_nbucket_ -
            reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];

        if (!powerof2(gnu_maskwords_)) {
          DL_ERR("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
              gnu_maskwords_, get_realpath());
          return false;
        }
        --gnu_maskwords_;

        flags_ |= FLAG_GNU_HASH;
        break;
		// 字符串表
      case DT_STRTAB:
        strtab_ = reinterpret_cast<const char*>(load_bias + d->d_un.d_ptr);
        break;
		// 字符串表大小
      case DT_STRSZ:
        strtab_size_ = d->d_un.d_val;
        break;
		// 符号表
      case DT_SYMTAB:
        symtab_ = reinterpret_cast<ElfW(Sym)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_SYMENT:
        if (d->d_un.d_val != sizeof(ElfW(Sym))) {
          DL_ERR("invalid DT_SYMENT: %zd in \"%s\"",
              static_cast<size_t>(d->d_un.d_val), get_realpath());
          return false;
        }
        break;
		// PLT 重定位使用的重定位条目类型
      case DT_PLTREL:
#if defined(USE_RELA)
        if (d->d_un.d_val != DT_RELA) {
          DL_ERR("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", get_realpath());
          return false;
        }
#else
        if (d->d_un.d_val != DT_REL) {
          DL_ERR("unsupported DT_PLTREL in \"%s\"; expected DT_REL", get_realpath());
          return false;
        }
#endif
        break;
		// PLT 重定位表在内存中的地址
      case DT_JMPREL:
#if defined(USE_RELA)
        plt_rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
#else
        plt_rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
#endif
        break;
		//  PLT 重定位表大小
      case DT_PLTRELSZ:
#if defined(USE_RELA)
        plt_rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
#else
        plt_rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
        break;
		// PLT 和/或 GOT 在内存中的地址
      case DT_PLTGOT:
        // Ignored (because RTLD_LAZY is not supported).
        break;

      case DT_DEBUG:
        // Set the DT_DEBUG entry to the address of _r_debug for GDB
        // if the dynamic table is writable
        if ((dynamic_flags & PF_W) != 0) {
          d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);
        }
        break;
#if defined(USE_RELA)
      case DT_RELA:
        rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELASZ:
        rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
        break;

      case DT_ANDROID_RELA:
        android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_ANDROID_RELASZ:
        android_relocs_size_ = d->d_un.d_val;
        break;

      case DT_ANDROID_REL:
        DL_ERR("unsupported DT_ANDROID_REL in \"%s\"", get_realpath());
        return false;

      case DT_ANDROID_RELSZ:
        DL_ERR("unsupported DT_ANDROID_RELSZ in \"%s\"", get_realpath());
        return false;

      case DT_RELAENT:
        if (d->d_un.d_val != sizeof(ElfW(Rela))) {
          DL_ERR("invalid DT_RELAENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      // Ignored (see DT_RELCOUNT comments for details).
      case DT_RELACOUNT:
        break;

      case DT_REL:
        DL_ERR("unsupported DT_REL in \"%s\"", get_realpath());
        return false;

      case DT_RELSZ:
        DL_ERR("unsupported DT_RELSZ in \"%s\"", get_realpath());
        return false;

#else
      case DT_REL:
        rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELSZ:
        rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
        break;

      case DT_RELENT:
        if (d->d_un.d_val != sizeof(ElfW(Rel))) {
          DL_ERR("invalid DT_RELENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      case DT_ANDROID_REL:
        android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_ANDROID_RELSZ:
        android_relocs_size_ = d->d_un.d_val;
        break;

      case DT_ANDROID_RELA:
        DL_ERR("unsupported DT_ANDROID_RELA in \"%s\"", get_realpath());
        return false;

      case DT_ANDROID_RELASZ:
        DL_ERR("unsupported DT_ANDROID_RELASZ in \"%s\"", get_realpath());
        return false;

      // "Indicates that all RELATIVE relocations have been concatenated together,
      // and specifies the RELATIVE relocation count."
      //
      // TODO: Spec also mentions that this can be used to optimize relocation process;
      // Not currently used by bionic linker - ignored.
      case DT_RELCOUNT:
        break;

      case DT_RELA:
        DL_ERR("unsupported DT_RELA in \"%s\"", get_realpath());
        return false;

      case DT_RELASZ:
        DL_ERR("unsupported DT_RELASZ in \"%s\"", get_realpath());
        return false;

#endif
      case DT_RELR:
      case DT_ANDROID_RELR:
        relr_ = reinterpret_cast<ElfW(Relr)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELRSZ:
      case DT_ANDROID_RELRSZ:
        relr_count_ = d->d_un.d_val / sizeof(ElfW(Relr));
        break;

      case DT_RELRENT:
      case DT_ANDROID_RELRENT:
        if (d->d_un.d_val != sizeof(ElfW(Relr))) {
          DL_ERR("invalid DT_RELRENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      // Ignored (see DT_RELCOUNT comments for details).
      // There is no DT_RELRCOUNT specifically because it would only be ignored.
      case DT_ANDROID_RELRCOUNT:
        break;
		// 初始化函数
      case DT_INIT:
        init_func_ = reinterpret_cast<linker_ctor_function_t>(load_bias + d->d_un.d_ptr);
        DEBUG("%s constructors (DT_INIT) found at %p", get_realpath(), init_func_);
        break;
		// 析构函数
      case DT_FINI:
        fini_func_ = reinterpret_cast<linker_dtor_function_t>(load_bias + d->d_un.d_ptr);
        DEBUG("%s destructors (DT_FINI) found at %p", get_realpath(), fini_func_);
        break;
		// .init_array 初始化函数列表
      case DT_INIT_ARRAY:
        init_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
        DEBUG("%s constructors (DT_INIT_ARRAY) found at %p", get_realpath(), init_array_);
        break;
		// .init_array 大小
      case DT_INIT_ARRAYSZ:
        init_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
        break;
		// .fini_array 析构函数列表
      case DT_FINI_ARRAY:
        fini_array_ = reinterpret_cast<linker_dtor_function_t*>(load_bias + d->d_un.d_ptr);
        DEBUG("%s destructors (DT_FINI_ARRAY) found at %p", get_realpath(), fini_array_);
        break;
		// .fini_array 大小
      case DT_FINI_ARRAYSZ:
        fini_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
        break;
		//初始化函数,大多只出现在可执行文件中,在so中忽略
		// 在bionic/linker/linker_soinfo.cpp中有明确注释
		// DT_PREINIT_ARRAY functions are called before any other constructors for executables,
		// but ignored in a shared library.
      case DT_PREINIT_ARRAY:
        preinit_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
        DEBUG("%s constructors (DT_PREINIT_ARRAY) found at %p", get_realpath(), preinit_array_);
        break;

      case DT_PREINIT_ARRAYSZ:
        preinit_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
        break;

      case DT_TEXTREL:
#if defined(__LP64__)
        DL_ERR("\"%s\" has text relocations", get_realpath());
        return false;
#else
        has_text_relocations = true;
        break;
#endif

      case DT_SYMBOLIC:
        has_DT_SYMBOLIC = true;
        break;
		//当前so的依赖，仅做计数操作
      case DT_NEEDED:
        ++needed_count;
        break;

      case DT_FLAGS:
        if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
          DL_ERR("\"%s\" has text relocations", get_realpath());
          return false;
#else
          has_text_relocations = true;
#endif
        }
        if (d->d_un.d_val & DF_SYMBOLIC) {
          has_DT_SYMBOLIC = true;
        }
        break;

      case DT_FLAGS_1:
        set_dt_flags_1(d->d_un.d_val);

        if ((d->d_un.d_val & ~SUPPORTED_DT_FLAGS_1) != 0) {
          DL_WARN("Warning: \"%s\" has unsupported flags DT_FLAGS_1=%p "
                  "(ignoring unsupported flags)",
                  get_realpath(), reinterpret_cast<void*>(d->d_un.d_val));
        }
        break;

      // Ignored: "Its use has been superseded by the DF_BIND_NOW flag"
      case DT_BIND_NOW:
        break;

      case DT_VERSYM:
        versym_ = reinterpret_cast<ElfW(Versym)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_VERDEF:
        verdef_ptr_ = load_bias + d->d_un.d_ptr;
        break;
      case DT_VERDEFNUM:
        verdef_cnt_ = d->d_un.d_val;
        break;

      case DT_VERNEED:
        verneed_ptr_ = load_bias + d->d_un.d_ptr;
        break;

      case DT_VERNEEDNUM:
        verneed_cnt_ = d->d_un.d_val;
        break;

      case DT_RUNPATH:
        // this is parsed after we have strtab initialized (see below).
        break;

      case DT_TLSDESC_GOT:
      case DT_TLSDESC_PLT:
        // These DT entries are used for lazy TLSDESC relocations. Bionic
        // resolves everything eagerly, so these can be ignored.
        break;

#if defined(__aarch64__)
      case DT_AARCH64_BTI_PLT:
      case DT_AARCH64_PAC_PLT:
      case DT_AARCH64_VARIANT_PCS:
        // Ignored: AArch64 processor-specific dynamic array tags.
        break;
#endif

      default:
        if (!relocating_linker) {
          const char* tag_name;
          if (d->d_tag == DT_RPATH) {
            tag_name = "DT_RPATH";
          } else if (d->d_tag == DT_ENCODING) {
            tag_name = "DT_ENCODING";
          } else if (d->d_tag >= DT_LOOS && d->d_tag <= DT_HIOS) {
            tag_name = "unknown OS-specific";
          } else if (d->d_tag >= DT_LOPROC && d->d_tag <= DT_HIPROC) {
            tag_name = "unknown processor-specific";
          } else {
            tag_name = "unknown";
          }
          DL_WARN("Warning: \"%s\" unused DT entry: %s (type %p arg %p) (ignoring)",
                  get_realpath(),
                  tag_name,
                  reinterpret_cast<void*>(d->d_tag),
                  reinterpret_cast<void*>(d->d_un.d_val));
        }
        break;
    }
  }

  DEBUG("si->base = %p, si->strtab = %p, si->symtab = %p",
        reinterpret_cast<void*>(base), strtab_, symtab_);

  // Validity checks.
  if (relocating_linker && needed_count != 0) {
    DL_ERR("linker cannot have DT_NEEDED dependencies on other libraries");
    return false;
  }
  if (nbucket_ == 0 && gnu_nbucket_ == 0) {
    DL_ERR("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
        "(new hash type from the future?)", get_realpath());
    return false;
  }
  if (strtab_ == nullptr) {
    DL_ERR("empty/missing DT_STRTAB in \"%s\"", get_realpath());
    return false;
  }
  if (symtab_ == nullptr) {
    DL_ERR("empty/missing DT_SYMTAB in \"%s\"", get_realpath());
    return false;
  }

  // Second pass - parse entries relying on strtab. Skip this while relocating the linker so as to
  // avoid doing heap allocations until later in the linker's initialization.
  if (!relocating_linker) {
    for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
      switch (d->d_tag) {
        case DT_SONAME:
          set_soname(get_string(d->d_un.d_val));
          break;
        case DT_RUNPATH:
          set_dt_runpath(get_string(d->d_un.d_val));
          break;
      }
    }
  }

  // Before M release, linker was using basename in place of soname. In the case when DT_SONAME is
  // absent some apps stop working because they can't find DT_NEEDED library by soname. This
  // workaround should keep them working. (Applies only for apps targeting sdk version < M.) Make
  // an exception for the main executable, which does not need to have DT_SONAME. The linker has an
  // DT_SONAME but the soname_ field is initialized later on.
  if (soname_.empty() && this != solist_get_somain() && !relocating_linker &&
      get_application_target_sdk_version() < 23) {
    soname_ = basename(realpath_.c_str());
    DL_WARN_documented_change(23, "missing-soname-enforced-for-api-level-23",
                              "\"%s\" has no DT_SONAME (will use %s instead)", get_realpath(),
                              soname_.c_str());

    // Don't call add_dlwarning because a missing DT_SONAME isn't important enough to show in the UI
  }

  // Validate each library's verdef section once, so we don't have to validate
  // it each time we look up a symbol with a version.
  if (!validate_verdef_section(this)) return false;

  flags_ |= FLAG_PRELINKED;
  return true;
}
```

#### 2.10.6. Step 5: 收集局部组根
收集局部组的根库（跨越命名空间边界的库），为后续链接局部组准备根节点。
```cpp
// bionic/linker/linker.cpp
// Step 5: Collect roots of local_groups.
  // Whenever needed_by->si link crosses a namespace boundary it forms its own local_group.
  // Here we collect new roots to link them separately later on. Note that we need to avoid
  // collecting duplicates. Also the order is important. They need to be linked in the same
  // BFS order we link individual libraries.
  std::vector<soinfo*> local_group_roots;
  if (start_with != nullptr && add_as_children) {
    local_group_roots.push_back(start_with);
  } else {
    CHECK(soinfos_count == 1);
    local_group_roots.push_back(soinfos[0]);
  }

  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    soinfo* needed_by = task->get_needed_by();
    bool is_dt_needed = needed_by != nullptr && (needed_by != start_with || add_as_children);
    android_namespace_t* needed_by_ns =
        is_dt_needed ? needed_by->get_primary_namespace() : ns;

    if (!si->is_linked() && si->get_primary_namespace() != needed_by_ns) {
      auto it = std::find(local_group_roots.begin(), local_group_roots.end(), si);
      LD_LOG(kLogDlopen,
             "Crossing namespace boundary (si=%s@%p, si_ns=%s@%p, needed_by=%s@%p, ns=%s@%p, needed_by_ns=%s@%p) adding to local_group_roots: %s",
             si->get_realpath(),
             si,
             si->get_primary_namespace()->get_name(),
             si->get_primary_namespace(),
             needed_by == nullptr ? "(nullptr)" : needed_by->get_realpath(),
             needed_by,
             ns->get_name(),
             ns,
             needed_by_ns->get_name(),
             needed_by_ns,
             it == local_group_roots.end() ? "yes" : "no");

      if (it == local_group_roots.end()) {
        local_group_roots.push_back(si);
      }
    }
  }
```

#### 2.10.7. Step 6: 链接所有局部组
链接每个局部组中的库，完成符号解析和重定位。完成库的动态链接，使其可用。


```cpp
// bionic/linker/linker.cpp
 // Step 6: Link all local groups
  for (auto root : local_group_roots) {
    soinfo_list_t local_group;
    android_namespace_t* local_group_ns = root->get_primary_namespace();

    walk_dependencies_tree(root,
      [&] (soinfo* si) {
        if (local_group_ns->is_accessible(si)) {
          local_group.push_back(si);
          return kWalkContinue;
        } else {
          return kWalkSkip;
        }
      });

    soinfo_list_t global_group = local_group_ns->get_global_group();
    SymbolLookupList lookup_list(global_group, local_group);
    soinfo* local_group_root = local_group.front();

    bool linked = local_group.visit([&](soinfo* si) {
      // Even though local group may contain accessible soinfos from other namespaces
      // we should avoid linking them (because if they are not linked -> they
      // are in the local_group_roots and will be linked later).
      if (!si->is_linked() && si->get_primary_namespace() == local_group_ns) {
        const android_dlextinfo* link_extinfo = nullptr;
        if (si == soinfos[0] || reserved_address_recursive) {
          // Only forward extinfo for the first library unless the recursive
          // flag is set.
          link_extinfo = extinfo;
        }
        if (__libc_shared_globals()->load_hook) {
          __libc_shared_globals()->load_hook(si->load_bias, si->phdr, si->phnum);
        }
        lookup_list.set_dt_symbolic_lib(si->has_DT_SYMBOLIC ? si : nullptr);
        if (!si->link_image(lookup_list, local_group_root, link_extinfo, &relro_fd_offset) ||
            !get_cfi_shadow()->AfterLoad(si, solist_get_head())) {
          return false;
        }
      }

      return true;
    });

    if (!linked) {
      return false;
    }
  }
```

当把所有的本地组和全局组加入到 `lookup_list` 中后，就开始调用 `si->link_image` 来对这些库进行链接的操作
```c
// bionic/linker/linker.cpp
bool soinfo::link_image(const SymbolLookupList& lookup_list, soinfo* local_group_root,
                        const android_dlextinfo* extinfo, size_t* relro_fd_offset) {
  if (is_image_linked()) {
    // already linked.
    return true;
  }

  if (g_is_ldd && !is_main_executable()) {
    async_safe_format_fd(STDOUT_FILENO, "\t%s => %s (%p)\n", get_soname(),
                         get_realpath(), reinterpret_cast<void*>(base));
  }

  local_group_root_ = local_group_root;
  if (local_group_root_ == nullptr) {
    local_group_root_ = this;
  }

  if ((flags_ & FLAG_LINKER) == 0 && local_group_root_ == this) {
    target_sdk_version_ = get_application_target_sdk_version();
  }

#if !defined(__LP64__)
  if (has_text_relocations) {
    // Fail if app is targeting M or above.
    int app_target_api_level = get_application_target_sdk_version();
    if (app_target_api_level >= 23) {
      DL_ERR_AND_LOG("\"%s\" has text relocations (%s#Text-Relocations-Enforced-for-API-level-23)",
                     get_realpath(), kBionicChangesUrl);
      return false;
    }
    // Make segments writable to allow text relocations to work properly. We will later call
    // phdr_table_protect_segments() after all of them are applied.
    DL_WARN_documented_change(23,
                              "Text-Relocations-Enforced-for-API-level-23",
                              "\"%s\" has text relocations",
                              get_realpath());
    add_dlwarning(get_realpath(), "text relocations");
    if (phdr_table_unprotect_segments(phdr, phnum, load_bias) < 0) {
      DL_ERR("can't unprotect loadable segments for \"%s\": %s", get_realpath(), strerror(errno));
      return false;
    }
  }
#endif

  if (!relocate(lookup_list)) {
    return false;
  }

  DEBUG("[ finished linking %s ]", get_realpath());

#if !defined(__LP64__)
  if (has_text_relocations) {
    // All relocations are done, we can protect our segments back to read-only.
    if (phdr_table_protect_segments(phdr, phnum, load_bias) < 0) {
      DL_ERR("can't protect segments for \"%s\": %s",
             get_realpath(), strerror(errno));
      return false;
    }
  }
#endif

  // We can also turn on GNU RELRO protection if we're not linking the dynamic linker
  // itself --- it can't make system calls yet, and will have to call protect_relro later.
  if (!is_linker() && !protect_relro()) {
    return false;
  }

  /* Handle serializing/sharing the RELRO segment */
  if (extinfo && (extinfo->flags & ANDROID_DLEXT_WRITE_RELRO)) {
    if (phdr_table_serialize_gnu_relro(phdr, phnum, load_bias,
                                       extinfo->relro_fd, relro_fd_offset) < 0) {
      DL_ERR("failed serializing GNU RELRO section for \"%s\": %s",
             get_realpath(), strerror(errno));
      return false;
    }
  } else if (extinfo && (extinfo->flags & ANDROID_DLEXT_USE_RELRO)) {
    if (phdr_table_map_gnu_relro(phdr, phnum, load_bias,
                                 extinfo->relro_fd, relro_fd_offset) < 0) {
      DL_ERR("failed mapping GNU RELRO section for \"%s\": %s",
             get_realpath(), strerror(errno));
      return false;
    }
  }

  ++g_module_load_counter;
  notify_gdb_of_load(this);
  set_image_linked();frelocate
  return true;
}
```
在 `soinfo::link_image` 中调用了 `relocate` 去进行符号的重定位
- 使用显示加数的和未使用显示加数的分类处理
- 调用两次`plain_relocate()`，分别对`.rel.dyn`和`.rel.plt`节区中的重定位信息进行重定位

```cpp
// bionic/linker/linker_relocate
bool soinfo::relocate(const SymbolLookupList& lookup_list) {

  VersionTracker version_tracker;

  if (!version_tracker.init(this)) {
    return false;
  }

  Relocator relocator(version_tracker, lookup_list);
  relocator.si = this;
  relocator.si_strtab = strtab_;
  relocator.si_strtab_size = has_min_version(1) ? strtab_size_ : SIZE_MAX;
  relocator.si_symtab = symtab_;
  relocator.tlsdesc_args = &tlsdesc_args_;
  relocator.tls_tp_base = __libc_shared_globals()->static_tls_layout.offset_thread_pointer();

  if (android_relocs_ != nullptr) {
    // check signature
    if (android_relocs_size_ > 3 &&
        android_relocs_[0] == 'A' &&
        android_relocs_[1] == 'P' &&
        android_relocs_[2] == 'S' &&
        android_relocs_[3] == '2') {
      DEBUG("[ android relocating %s ]", get_realpath());

      const uint8_t* packed_relocs = android_relocs_ + 4;
      const size_t packed_relocs_size = android_relocs_size_ - 4;

      if (!packed_relocate<RelocMode::Typical>(relocator, sleb128_decoder(packed_relocs, packed_relocs_size))) {
        return false;
      }
    } else {
      DL_ERR("bad android relocation header.");
      return false;
    }
  }

  if (relr_ != nullptr) {
    DEBUG("[ relocating %s relr ]", get_realpath());
    if (!relocate_relr()) {
      return false;
    }
  }

#if defined(USE_RELA)    //如果使用了显式加数（一般64位使用）
  if (rela_ != nullptr) { 
    DEBUG("[ relocating %s rela ]", get_realpath());

    if (!plain_relocate<RelocMode::Typical>(relocator, rela_, rela_count_)) {
      return false;
    }
  }
  if (plt_rela_ != nullptr) {
    DEBUG("[ relocating %s plt rela ]", get_realpath());
    if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rela_, plt_rela_count_)) {
      return false;
    }
  }
#else    //如果没有使用显式加数（一般32位使用）
  if (rel_ != nullptr) {
  //.rel.dyn节区中的重定位信息进行重定位
    DEBUG("[ relocating %s rel ]", get_realpath());
    if (!plain_relocate<RelocMode::Typical>(relocator, rel_, rel_count_)) {
      return false;
    }
  }
  if (plt_rel_ != nullptr) {
  //.rel.plt节区中的重定位信息进行重定位
    DEBUG("[ relocating %s plt rel ]", get_realpath());
    if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rel_, plt_rel_count_)) {
      return false;
    }
  }
#endif

  // Once the tlsdesc_args_ vector's size is finalized, we can write the addresses of its elements
  // into the TLSDESC relocations.
#if defined(__aarch64__)
  // Bionic currently only implements TLSDESC for arm64.
  for (const std::pair<TlsDescriptor*, size_t>& pair : relocator.deferred_tlsdesc_relocs) {
    TlsDescriptor* desc = pair.first;
    desc->func = tlsdesc_resolver_dynamic;
    desc->arg = reinterpret_cast<size_t>(&tlsdesc_args_[pair.second]);
  }
#endif

  return true;
}
```

`plain_relocate()`->`plain_relocate_impl()`->`process_relocation()`->`process_relocation_impl()`
- `process_relocation_impl`最终会对`.rel.plt`和`.rel.dyn`节区中指向的重定位数据进行修正
- 对于`R_GENERIC_JUMP_SLOT`，`R_GENERIC_GLOB_DAT`和`R_GENRIC_ABCOLUTE`类型的重定位数据只需找到其重定位数据对应的符号并获取到实际内存地址，然后写回修正即可
- 对于`R_GENERIC_RELATIVE`类型的重定位数据需要获取其原来相对与0基地址的值，加上实际的内存加载基地址，然后写回修正即可
```cpp
// bionic/linker/linker_relocate.cpp
static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
  constexpr bool IsGeneral = Mode == RelocMode::General;
  //relocator.si->load_bias为模块实际的加载基地址
  //rel_target为对应的待重定位数据的实际内存地址（.got表项的地址）
  void* const rel_target = reinterpret_cast<void*>(reloc.r_offset + relocator.si->load_bias);

  //r_type为重定位类型
  const uint32_t r_type = ELFW(R_TYPE)(reloc.r_info);
  //r_sym为对应重定位数据的符号表索引
  const uint32_t r_sym = ELFW(R_SYM)(reloc.r_info);

  //利用r_sym符号表索引从.symtab中获取对应的表项，并利用表项的st_name字段在.dynstr中找到对应的重定位符号字符串
  if (r_sym != 0) {
    sym_name = relocator.get_string(relocator.si_symtab[r_sym].st_name);
  }
  
  #if defined(USE_RELA)      //如果使用了显式加数
    auto get_addend_rel   = [&]() -> ElfW(Addr) { return reloc.r_addend; };
    auto get_addend_norel = [&]() -> ElfW(Addr) { return reloc.r_addend; };
  #else                      //如果没使用显示加数
    auto get_addend_rel   = [&]() -> ElfW(Addr) { return *static_cast<ElfW(Addr)*>(rel_target); };
    auto get_addend_norel = [&]() -> ElfW(Addr) { return 0; };
  #endif

  //symaddr = 对应符号实际在内存中的地址
  //一下解析以没有使用显式加数的为例
  if constexpr (IsGeneral || Mode == RelocMode::JumpTable) {
    //R_GENERIC_JUMP_SLOT是函数引用的重定位类型
    if (r_type == R_GENERIC_JUMP_SLOT) {

      count_relocation_if<IsGeneral>(kRelocAbsolute);
      const ElfW(Addr) result = sym_addr + get_addend_norel();  //get_addend_norel()返回0，result = symaddr
      trace_reloc("RELO JMP_SLOT %16p <- %16p %s",
                  rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;           //需要重定位的数据修正为sym_addr，即其内存中的实际地址
      return true;
    }
  }

  if constexpr (IsGeneral || Mode == RelocMode::Typical) {
    //R_GENERIC_ABSOLUTE为数据引用的重定位类型
    if (r_type == R_GENERIC_ABSOLUTE) {

      count_relocation_if<IsGeneral>(kRelocAbsolute);
      const ElfW(Addr) result = sym_addr + get_addend_rel();  //get_addend_rel()返回重定位的数据的值，但其实际重定位的数据的值也为0。result = symaddr
      trace_reloc("RELO ABSOLUTE %16p <- %16p %s",
                  rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    } 
    //R_GENERIC_GLOB_DAT为数据引用的重定位类型
    else if (r_type == R_GENERIC_GLOB_DAT) {

      count_relocation_if<IsGeneral>(kRelocAbsolute);
      const ElfW(Addr) result = sym_addr + get_addend_norel();  //get_addend_norel()返回0，result = symaddr
      trace_reloc("RELO GLOB_DAT %16p <- %16p %s",
                  rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;           //需要重定位的数据修正为symaddr，即其内存中的实际地址
      return true;
    }
     //R_GENERIC_RELATIVE为静态或全局变量引用的重定位类型
     else if (r_type == R_GENERIC_RELATIVE) {
      
      count_relocation_if<IsGeneral>(kRelocRelative);                      //get_addend_rel()返回重定位的数据的值 
      const ElfW(Addr) result = relocator.si->load_bias + get_addend_rel();//result = 基地址 + get_addend_rel()返回重定位的数据的值 
      trace_reloc("RELO RELATIVE %16p <- %16p",
                  rel_target, reinterpret_cast<void*>(result));
      *static_cast<ElfW(Addr)*>(rel_target) = result;            //需要重定位的数据修正为：基地址 + get_addend_rel()返回重定位的数据的值，即指针指向的静态或全局变量实际的内存地址
      return true;
    }
  }


```
#### 2.10.8. Step 7: 标记已链接并更新引用计数
标记所有库为已链接，并管理引用计数。将 `start_with` 和所有任务中的库标记为已链接，对于跨局部组引用的库，增加引用计数。确保库的状态一致，并防止意外卸载。
```cpp
// bionic/linker/linker.cpp
  // Step 7: Mark all load_tasks as linked and increment refcounts
  // for references between load_groups (at this point it does not matter if
  // referenced load_groups were loaded by previous dlopen or as part of this
  // one on step 6)
  if (start_with != nullptr && add_as_children) {
    start_with->set_linked();
  }

  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    si->set_linked();
  }

  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    soinfo* needed_by = task->get_needed_by();
    if (needed_by != nullptr &&
        needed_by != start_with &&
        needed_by->get_local_group_root() != si->get_local_group_root()) {
      si->increment_ref_count();
    }
  }

```

## 3. 加壳技术
在病毒和版权保护领域，“壳”一直扮演着极为重要的角色。通过加壳可以对代码进行压缩和加密，同时再辅以虚拟化、代码混淆和反调试等手段，达到防止静态和动态分析。

在 Android 环境中，Native 层的加壳主要是针对动态链接库 SO，SO 加壳的示意图如下:
![](https://cdn.jsdelivr.net/gh/Asu1tty/blog_img@master/picSource/v2-b86226be6c03dbefee9ca83081b74c0d_1440w.png)
加壳工具、loader、被保护SO。
- **SO**: 即被保护的目标 SO。
- **loader**: 自身也是一个 SO，系统加载时首先加载 loader，loader 首先还原出经过加密、压缩、变换的 SO，再将 SO 加载到内存，并完成链接过程，使 SO 可以正常被其他模块使用。
- **加壳工具**: 将被保护的 SO 加密、压缩、变换，并将结果作为数据与 loader 整合为 packed SO。
下面对 SO 加壳的关键技术进行简单介绍。
### 3.1. loader 执行时机
Linker 加载完 loader 后，loader 需要将被保护的 SO 加载起来，这就要求 loader 的代码需要被执行，而且要在 被保护 SO 被使用之前，前文介绍了 SO 的初始化函数便可以满足这个要求，同时在 Android 系统下还可以使用 JNI_ONLOAD 函数，因此 loader 的执行时机有两个选择:
- SO 的 init 或 initarray
- jni_onload
### 3.2. loader 完成 SO 的加载链接
loader 开始执行后，首先需要在内存中还原出 SO，SO 可以是经过加密、压缩、变换等手段，也可已单纯的以完全明文的数据存储，这与 SO 加壳的技术没有必要的关系，在此不进行讨论。  

在内存中还原出 SO 后，loader 还需要执行装载和链接，这两个过程可以完全模仿 Linker 来实现，下面主要介绍一下相对 Linker，loader 执行这两个过程有哪些变化。
#### 3.2.1. 装载
还原后的 SO 在内存中，所以装载时的主要变化就是从文件装载到从内存装载。  
Linker 在装载 PT_LAOD segment时，即`LoadSegments()`中，使用 SO 文件的描述符 fd：
```cpp
// bionic/linker/linker_phdr.cpp
void* seg_addr = mmap(reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size,
                          prot | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```
按照 Linker 装载，PT_LAOD segment时，需要分为两步：
```cpp
// 1、改用匿名映射
void* seg_addr = mmap(reinterpret_cast<void*>(seg_page_start),
                      seg_page_aligned_size,
                      prot | PROT_WRITE,
                      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                      -1,
                      0);
  // 2、将内存中的 segment 复制到映射的内存中
  memcpy(seg_addr+seg_page_offset, elf_data_buf + phdr->p_offset, phdr->p_filesz);
```
注意第2步复制 segment 时，目标地址需要加上 seg_page_offset，seg_page_offset 是 segment 相对与页面起始地址的偏移。  
其他的步骤基本按照 Linker 的实现即可，只需要将一些从文件读取修改为从内存读取，比如读 elfheader和program header时。
#### 3.2.2. 分配 soinfo
soinfo 保存了 SO 装载链接和运行时需要的所有信息，为了维护相关的信息，loader 可以照搬 Linker 的 soinfo 结构，用于存储中间信息，装载链接结束后，还需要将 soinfo 的信息修复到 Linker 维护的soinfo，3.3节进行详细说明。
#### 3.2.3. 链接
链接过程完全是操作内存，不论是从文件装载还是内存装载，链接过程都是一样，完全模仿 Linker 即可。  
另外链接后记得顺便调用 SO 初始化函数( init 和 init_array )。
### 3.3. soinfo 修复
SO 加壳的最关键技术点在于 soinfo 的修复，由于 Linker 加载的是 loader，而实际对外使用的是被保护的 SO，所以 Linker 维护的 soinfo 可以说是错误，loader 需要将自己维护的 soinfo 中的部分信息导出给 Linker 的soinfo。
修复过程如下：
1. 获取 Linker 维护的 soinfo，可以通过 dlopen 打开自己来获得：self_soinfo = dlopen(_self_)。
2. 将 loader soinfo 中的信息导出到 self_soinfo，最简单粗暴的方式就是直接赋值，比如：self_soinfo.base = soinfo.base。需要导出的主要有以下几项：
    - SO地址范围：base、size、load_bias
    - 符号信息:sym_tab、str_tab、
    - 符号查找信息：nbucket、nchain、bucket、chain
    - 异常处理：ARM_exidx、ARM_exidx_count

## 4. 参考资料
**本文章源自以下文章内容，仅作学习和记录使用**
- [安卓so加载流程源码分析](https://oacia.dev/android-load-so/)
- [android源码分析之linker初始化](https://www.cnblogs.com/revercc/p/16299712.html)
- [Android Linker 与 SO 加壳技术](https://zhuanlan.zhihu.com/p/22652847)
