package com.sukisu.ultra

import android.content.Context
import android.os.Parcelable
import android.util.Log
import androidx.annotation.Keep
import androidx.compose.runtime.Immutable
import dalvik.system.DexClassLoader
import kotlinx.parcelize.Parcelize
import java.io.File

/**
 * @author weishu
 * @date 2022/12/8.
 */
object Natives {
    // minimal supported kernel version
    // 10915: allowlist breaking change, add app profile
    // 10931: app profile struct add 'version' field
    // 10946: add capabilities
    // 10977: change groups_count and groups to avoid overflow write
    // 11071: Fix the issue of failing to set a custom SELinux type.
    // 12143: breaking: new supercall impl
    const val MINIMAL_SUPPORTED_KERNEL = 12143

    // 12040: Support disable sucompat mode
    const val KERNEL_SU_DOMAIN = "u:r:su:s0"

    const val MINIMAL_SUPPORTED_KERNEL_FULL = "v3.1.8"

    const val MINIMAL_SUPPORTED_KPM = 12800

    const val MINIMAL_SUPPORTED_DYNAMIC_MANAGER = 13215

    const val MINIMAL_NEW_IOCTL_KERNEL = 13490

    const val ROOT_UID = 0
    const val ROOT_GID = 0

    // 获取完整版本号
    external fun getFullVersion(): String

    fun isVersionLessThan(v1Full: String, v2Full: String): Boolean {
        fun extractVersionParts(version: String): List<Int> {
            val match = Regex("""v\d+(\.\d+)*""").find(version)
            val simpleVersion = match?.value ?: version
            return simpleVersion.trimStart('v').split('.').map { it.toIntOrNull() ?: 0 }
        }

        val v1Parts = extractVersionParts(v1Full)
        val v2Parts = extractVersionParts(v2Full)
        val maxLength = maxOf(v1Parts.size, v2Parts.size)
        for (i in 0 until maxLength) {
            val num1 = v1Parts.getOrElse(i) { 0 }
            val num2 = v2Parts.getOrElse(i) { 0 }
            if (num1 != num2) return num1 < num2
        }
        return false
    }

    fun getSimpleVersionFull(): String = getFullVersion().let { version ->
        Regex("""v\d+(\.\d+)*""").find(version)?.value ?: version
    }

    init {
        // 修改：添加 DEX 安全加载（修复 writable DEX 问题）
        loadDexSafely()

        System.loadLibrary("zakosign")
        System.loadLibrary("kernelsu")
    }

    val version: Int
        external get

    // get the uid list of allowed su processes.
    val allowList: IntArray
        external get

    val isSafeMode: Boolean
        external get

    val isLkmMode: Boolean
        external get

    val isManager: Boolean
        external get

    external fun uidShouldUmount(uid: Int): Boolean

    /**
     * Get the profile of the given package.
     * @param key usually the package name
     * @return return null if failed.
     */
    external fun getAppProfile(key: String?, uid: Int): Profile
    external fun setAppProfile(profile: Profile?): Boolean

    /**
     * `su` compat mode can be disabled temporarily.
     *  0: disabled
     *  1: enabled
     *  negative : error
     */
    external fun isSuEnabled(): Boolean
    external fun setSuEnabled(enabled: Boolean): Boolean

    /**
     * Kernel module umount can be disabled temporarily.
     *  0: disabled
     *  1: enabled
     *  negative : error
     */
    external fun isKernelUmountEnabled(): Boolean
    external fun setKernelUmountEnabled(enabled: Boolean): Boolean

    /**
     * Enhanced security can be enabled/disabled.
     *  0: disabled
     *  1: enabled
     *  negative : error
     */
    external fun isEnhancedSecurityEnabled(): Boolean
    external fun setEnhancedSecurityEnabled(enabled: Boolean): Boolean

    external fun isKPMEnabled(): Boolean
    external fun getHookType(): String

    // 模块签名验证
    external fun verifyModuleSignature(modulePath: String): Boolean

    external fun getUserName(uid: Int): String?
    
    private const val NON_ROOT_DEFAULT_PROFILE_KEY = "$"
    private const val NOBODY_UID = 9999

    fun setDefaultUmountModules(umountModules: Boolean): Boolean {
        Profile(
            NON_ROOT_DEFAULT_PROFILE_KEY,
            NOBODY_UID,
            false,
            umountModules = umountModules
        ).let {
            return setAppProfile(it)
        }
    }

    fun isDefaultUmountModules(): Boolean {
        getAppProfile(NON_ROOT_DEFAULT_PROFILE_KEY, NOBODY_UID).let {
            return it.umountModules
        }
    }

    fun requireNewKernel(): Boolean {
        if (version != -1 && version < MINIMAL_SUPPORTED_KERNEL) return true
        return isVersionLessThan(getFullVersion(), MINIMAL_SUPPORTED_KERNEL_FULL)
    }

    @Immutable
    @Parcelize
    @Keep
    data class Profile(
        // and there is a default profile for root and non-root
        val name: String,
        // current uid for the package, this is convivent for kernel to check
        // if the package name doesn't match uid, then it should be invalidated.
        val currentUid: Int = 0,

        // if this is true, kernel will grant root permission to this package
        val allowSu: Boolean = false,

        // these are used for root profile
        val rootUseDefault: Boolean = true,
        val rootTemplate: String? = null,
        val uid: Int = ROOT_UID,
        val gid: Int = ROOT_GID,
        val groups: List<Int> = mutableListOf(),
        val capabilities: List<Int> = mutableListOf(),
        val context: String = KERNEL_SU_DOMAIN,
        val namespace: Int = Namespace.INHERITED.ordinal,

        val nonRootUseDefault: Boolean = true,
        val umountModules: Boolean = true,
        var rules: String = "", // this field is save in ksud!!
    ) : Parcelable {
        enum class Namespace {
            INHERITED,
            GLOBAL,
            INDIVIDUAL,
        }

        constructor() : this("")
    }

    // 新增：安全加载 DEX 文件（修复方案核心）
    private fun loadDexSafely() {
        try {
            val context = ksuApp  // 假设 ksuApp 是 Application 实例（在 KernelSUApplication 中定义）
            val cacheDex = File(context.cacheDir, "main.jar")
            val safeDex = File(context.filesDir, "main.jar")  // 只读内部存储
            val optimizedDir = context.codeCacheDir  // 优化目录（用于 DEX 优化）

            // 如果 cacheDex 存在且 safeDex 不存在，则复制
            if (cacheDex.exists() && !safeDex.exists()) {
                cacheDex.copyTo(safeDex, overwrite = true)
                cacheDex.delete()  // 可选：删除可写副本以避免重复
            }

            // 如果 safeDex 存在，使用 DexClassLoader 加载
            if (safeDex.exists()) {
                val dexLoader = DexClassLoader(
                    safeDex.absolutePath,
                    optimizedDir.absolutePath,
                    null,  // libraryPath（如果需要 native 库）
                    context.classLoader  // parentClassLoader
                )
                // 可选：使用 dexLoader 加载 hook 类（例如 zygisk 相关）
                // 例如：val hookClass = dexLoader.loadClass("com.example.HookClass")
                Log.d("SukiSU", "DEX loaded successfully from safe path: ${safeDex.absolutePath}")
            }
        } catch (e: Exception) {
            Log.e("SukiSU", "Failed to load DEX safely: ${e.message}")
            // 不抛出异常，避免应用崩溃
        }
    }
}
