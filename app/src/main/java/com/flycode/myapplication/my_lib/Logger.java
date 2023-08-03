package com.flycode.myapplication.my_lib;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;

public class Logger {
    private static String fileName;

    public static void init(String filePath){
        fileName = filePath;
    }
    public static void append(String line){
        try(FileOutputStream writer = new FileOutputStream(fileName,true)) {
            writer.write(line.getBytes());
            writer.write('\n');
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void clearLog(){
        try(FileOutputStream fileOutputStream = new FileOutputStream(fileName, false);) {
            String newLog = "Журнал очищен:" + new Date().toString();
            fileOutputStream.write(newLog.getBytes());
            fileOutputStream.write('\n');
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String exportLog(){
        StringBuilder s = new StringBuilder();
        try(FileReader reader = new FileReader(fileName)) {
            int character;
            while ((character = reader.read()) != -1){
                s.append((char) character);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return s.toString();
    }
}
