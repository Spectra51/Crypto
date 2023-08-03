package com.flycode.myapplication;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class DexFileList {
    public static void invoke(Context context) {
        // Получение пути к директории с файлами приложения
//        String appFilesDir = "/path/to/your/app/files"; // Замените на путь к директории вашего приложения
        File appFilesDir = context.getFilesDir();
        String appFilesPath = appFilesDir.getAbsolutePath();
        // Создание списка для хранения .dex файлов
        List<File> dexFiles = new ArrayList<>();

        // Получение списка файлов из директории приложения
        File appDir = new File(appFilesPath);
        File[] files = appDir.listFiles();

        // Фильтрация и добавление .dex файлов в список
        if (files != null) {
            for (File file : files) {
                if (file.isFile() && file.getName().endsWith(".dex")) {
                    dexFiles.add(file);
                }
            }
        }

        // Вывод списка .dex файлов
        for (File dexFile : dexFiles) {
            Log.d("DEX",dexFile.getAbsolutePath());
        }
    }
}
