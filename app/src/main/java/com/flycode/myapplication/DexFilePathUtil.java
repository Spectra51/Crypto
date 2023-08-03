package com.flycode.myapplication;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;

import java.io.File;

public class DexFilePathUtil {
    public static String getDexFilePath(@NonNull Context context) {
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && applicationInfo.splitSourceDirs != null) {
            // Для Android 5.0 (API 21) и новее с поддержкой мультисмычки (multidex)
            return applicationInfo.splitSourceDirs[0];
        } else {
            // Для Android до версии 5.0 и старше
            return applicationInfo.sourceDir;
        }
    }
}
