package com.flycode.myapplication;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class DexFileCopier {
    public static File copyDexFileToCache(Context context) throws IOException {
        // Получение пути к APK-файлу вашего приложения
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        String apkFilePath = applicationInfo.sourceDir;

        // Создание временной директории для копирования .dex файла
        File cacheDir = context.getExternalCacheDir(); // или используйте другую доступную директорию
        File tempDexFile = new File(cacheDir, "temp_classes.dex");

        // Копирование .dex файла из APK во временную директорию
        try (InputStream inputStream = context.getAssets().open(apkFilePath);
             OutputStream outputStream = new FileOutputStream(tempDexFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }

        return tempDexFile;
    }
}