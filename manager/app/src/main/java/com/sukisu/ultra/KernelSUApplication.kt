package com.sukisu.ultra

import android.app.Application
import android.system.Os
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import coil.Coil
import coil.ImageLoader
import com.dergoogler.mmrl.platform.Platform
import me.zhanghai.android.appiconloader.coil.AppIconFetcher
import me.zhanghai.android.appiconloader.coil.AppIconKeyer
import okhttp3.Cache
import okhttp3.OkHttpClient
import java.io.File
import java.util.Locale

lateinit var ksuApp: KernelSUApplication

class KernelSUApplication : Application(), ViewModelStoreOwner {

    lateinit var okhttpClient: OkHttpClient
    private val appViewModelStore by lazy { ViewModelStore() }

    override fun onCreate() {
        super.onCreate()
        ksuApp = this

        // For faster response when first entering superuser or webui activity
        val superUserViewModel = ViewModelProvider(this)[SuperUserViewModel::class.java]
        CoroutineScope(Dispatchers.Main).launch {
            superUserViewModel.fetchAppList()
        }

        Platform.setHiddenApiExemptions()

        val context = this
        val iconSize = resources.getDimensionPixelSize(android.R.dimen.app_icon_size)
        Coil.setImageLoader(
            ImageLoader.Builder(context)
                .components {
                    add(AppIconKeyer())
                    add(AppIconFetcher.Factory(iconSize, false, context))
                }
                .build()
        )

        val webroot = File(dataDir, "webroot")
        if (!webroot.exists()) {
            webroot.mkdir()
        }

        // 修改：设置 TMPDIR 到只读目录（filesDir），避免 DEX 在可写 cacheDir
        // 原始：Os.setenv("TMPDIR", cacheDir.absolutePath, true)
        Os.setenv("TMPDIR", filesDir.absolutePath, true)  // 或移除此行，使用系统默认

        okhttpClient =
            OkHttpClient.Builder()
                .cache(Cache(File(filesDir, "okhttp"), 10 * 1024 * 1024))  // 可选：缓存移到 filesDir
                .addInterceptor { block ->
                    block.proceed(
                        block.request().newBuilder()
                            .header("User-Agent", "SukiSU/${BuildConfig.VERSION_CODE}")
                            .header("Accept-Language", Locale.getDefault().toLanguageTag()).build()
                    )
                }.build()
    }
    override val viewModelStore: ViewModelStore
        get() = appViewModelStore
}
