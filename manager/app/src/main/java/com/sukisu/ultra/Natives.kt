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
    private const val TAG = "Natives"

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

    // --- 安全初始化逻辑 ---
    @Volatile
    private var isInitialized = false

    /**
     * 安全地初始化 DEX 和 native 库。
     * 必须在 Application.onCreate() 或之后调用。
     */
    fun initialize(context: Context) {
        if (isInitialized) return
        synchronized(this) {
            if (isInitialized) return

            try {
                loadDexSafely(context)
                System.loadLibrary("zakosign")
                System.loadLibrary("kernelsu")
                isInitialized = true
                Log.d(TAG, "Native libraries and DEX loaded successfully.")
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to initialize native components", e)
                throw RuntimeException("Native initialization failed", e)
            }
        }
    }

    // --- Native 方法声明 (保持原始签名) ---
    external fun getFullVersion(): String

    val version: Int
        external get

    val allowList: IntArray
        external get

    val isSafeMode: Boolean
        external get

    val isLkmMode: Boolean
        external get

    val isManager: Boolean
        external get

    external fun uidShouldUmount(uid: Int): Boolean

    external fun getAppProfile(key: String?, uid: Int): Profile
    external fun setAppProfile(profile: Profile?): Boolean

    external fun isSuEnabled(): Boolean
    external fun setSuEnabled(enabled: Boolean): Boolean

    external fun isKernelUmountEnabled(): Boolean
    external fun setKernelUmountEnabled(enabled: Boolean): Boolean

    external fun isEnhancedSecurityEnabled(): Boolean
    external fun setEnhancedSecurityEnabled(enabled: Boolean): Boolean

    external fun isKPMEnabled(): Boolean
    external fun getHookType(): String

    external fun verifyModuleSignature(modulePath: String): Boolean

    external fun getUserName(uid: Int): String?

    // --- 工具方法 ---
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
        val name: String,
        val currentUid: Int = 0,
        val allowSu: Boolean = false,
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
        var rules: String = "",
    ) : Parcelable {
        enum class Namespace {
            INHERITED,
            GLOBAL,
            INDIVIDUAL,
        }

        constructor() : this("")
    }

    // --- DEX 安全加载 ---
    private fun loadDexSafely(context: Context) {
        try {
            val cacheDex = File(context.cacheDir, "main.jar")
            val safeDex = File(context.filesDir, "main.jar")
            val optimizedDir = context.codeCacheDir

            if (cacheDex.exists() && !safeDex.exists()) {
                cacheDex.copyTo(safeDex, overwrite = true)
                cacheDex.delete()
            }

            if (safeDex.exists()) {
                DexClassLoader(
                    safeDex.absolutePath,
                    optimizedDir.absolutePath,
                    null,
                    context.classLoader
                )
                Log.d(TAG, "DEX loaded successfully from safe path: ${safeDex.absolutePath}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load DEX safely", e)
        }
    }
}