package com.sukisu.ultra

import android.app.Application
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import coil.Coil
import coil.ImageLoader
import com.dergoogler.mmrl.platform.Platform
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
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

        // IMPORTANT:
        // Do NOT override TMPDIR. On Android 15/16+, writable dex/jar generated under
        // app-private writable dirs (cacheDir/filesDir) may cause ART to abort when loaded.
        // Keep system default behavior.

        okhttpClient =
            OkHttpClient.Builder()
                // Cache belongs in cacheDir; it is not related to dex/jar loading, and should not
                // pollute filesDir.
                .cache(Cache(File(cacheDir, "okhttp"), 10 * 1024 * 1024))
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
