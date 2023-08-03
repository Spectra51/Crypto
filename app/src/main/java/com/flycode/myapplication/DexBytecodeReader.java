package com.flycode.myapplication;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;

import dalvik.system.DexFile;

public class DexBytecodeReader {

    public static void readClassBytecode(String dexFilePath, String className) {
        try (FileInputStream fis = new FileInputStream(new File(dexFilePath))) {
            // Чтение .dex файла в байтовый массив
            byte[] dexBytes = new byte[fis.available()];
            fis.read(dexBytes);

            // Поиск конкретного класса по имени
            int classOffset = findClassOffset(dexBytes, className);
            if (classOffset != -1) {
                // Получение размера байт-кода класса
                int classSize = readInt(dexBytes, classOffset + 32);

                // Получение байт-кода класса
                byte[] bytecode = new byte[classSize];
                System.arraycopy(dexBytes, classOffset + 36, bytecode, 0, classSize);

                // Вывод байт-кода в шестнадцатеричном формате
                for (byte b : bytecode) {
                    Log.d("DEX",String.format("%02X ", b));
//                    System.out.print(String.format("%02X ", b));
                }
            } else {
                Log.d("DEX","Class not found: " + className);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static int findClassOffset(byte[] dexBytes, String className) {
        int stringIdsSize = readInt(dexBytes, 72);
        int stringIdsOffset = readInt(dexBytes, 76);

        for (int i = 0; i < stringIdsSize; i++) {
            int stringOffset = stringIdsOffset + 4 * i;
            int stringDataOffset = readInt(dexBytes, stringOffset);

            int length = dexBytes[stringDataOffset];
            if (length == className.length()) {
                int j;
                for (j = 0; j < length; j++) {
                    if (dexBytes[stringDataOffset + 1 + j] != className.charAt(j)) {
                        break;
                    }
                }
                if (j == length) {
                    int typeIdsSize = readInt(dexBytes, 84);
                    int typeIdsOffset = readInt(dexBytes, 88);

                    int descriptorIdx = i + 1;
                    for (int k = 0; k < typeIdsSize; k++) {
                        if (readInt(dexBytes, typeIdsOffset + 4 * k) == descriptorIdx) {
                            int classDefsSize = readInt(dexBytes, 92);
                            int classDefsOffset = readInt(dexBytes, 96);
                            return readInt(dexBytes, classDefsOffset + 32 * k);
                        }
                    }
                }
            }
        }
        return -1;
    }

    private static int readInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8) | ((bytes[offset + 2] & 0xFF) << 16) | ((bytes[offset + 3] & 0xFF) << 24);
    }

    public static void execute(String dexFilePath,String className) {
        readClassBytecode(dexFilePath, className);
    }
}
