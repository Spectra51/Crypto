package com.flycode.myapplication;

import android.util.Log;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.function.Consumer;

public class DexFileReader {
    public static void read(String dexFilePath) {
        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(new FileInputStream(dexFilePath)))) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            ArrayList<String> list = new ArrayList<>();
            while ((bytesRead = dis.read(buffer)) != -1) {
                for (int i = 0; i < bytesRead; i++) {
                    list.add(String.format("%02X ", buffer[i]));
//                    str.append(String.format("%02X ", buffer[i]));
//                    Log.d("CLASS",String.format("%02X ", buffer[i])); // Вывод байтов в шестнадцатеричном формате
                }
            }
            Log.d("CLASS",list.size() + "");
            list.forEach(new Consumer<String>() {
                @Override
                public void accept(String s) {
                    Log.d("CLASS",s);
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
//         Путь к файлу .dex, который вы хотите прочитать
//
//        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(new FileInputStream(dexFilePath)))) {
//            // Пропуск магического числа и прочих заголовков
//            dis.skip(8);
//
//            // Чтение смещения таблицы строк
//            int stringsOffset = dis.readInt();
//
//            // Пропуск до таблицы смещений классов
//            dis.skip(stringsOffset - 12);
//
//            // Чтение количества классов
//            int classCount = dis.readUnsignedShort();
//
//            // Пропуск таблицы смещений интерфейсов и других данных
//            dis.skip(4 * classCount);
//
//            // Чтение таблицы смещений классов и вывод имен классов
//            for (int i = 0; i < classCount; i++) {
////                int classOffset = dis.readInt();
////                dis.skip(classOffset + 8); // Пропускаем флаги и смещение суперкласса
////
////                // Чтение индекса строки с именем класса
////                int classNameIndex = dis.readInt();
////
////                // Возврат к таблице строк и чтение имени класса
////                dis.reset();
////                dis.skip(stringsOffset + classNameIndex);
//                int nameLength = dis.readUnsignedShort();
//                byte[] nameBytes = new byte[nameLength];
//                dis.readFully(nameBytes);
//                String className = new String(nameBytes, "UTF-8");
//                Log.d("CLASS",className.replace('/', '.'));
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }
}
