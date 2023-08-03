package com.flycode.myapplication.my_lib;

import android.content.Context;
import android.content.SharedPreferences;

public class Storage {
    //TODO Singleton
    private Context mContext;
    private static final String STORAGE = "STORAGE";
    private static final String PASSWORD = "PASSWORD";
    private static final String PASSWORD_HASH = "PASSWORD_HASH";
    private static final String EXPIRES_DATE = "EXPIRES_DATE";
    private static final String SALT = "SALT";

    private SharedPreferences preferences = null;

    public Storage(Context context) {
        mContext = context;
        preferences = mContext.getSharedPreferences(STORAGE, Context.MODE_PRIVATE);
    }

    public void setSalt(byte[] value) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(SALT, value.toString());
        editor.apply();
    }

    public byte[] getSalt() {
        return preferences.getString(SALT, "").getBytes();
    }

    public void setPassword(String value) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(PASSWORD, value);
        editor.apply();
    }

    public String getPassword() {
        return preferences.getString(PASSWORD, "");
    }

    public void setPasswordHash(int value) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt(PASSWORD_HASH, value);
        editor.apply();
    }

    public int getPasswordHash() {
        return preferences.getInt(PASSWORD_HASH, 0);
    }

    public void setExpiresDate(int value) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt(EXPIRES_DATE, value);
        editor.apply();
    }

    public int getExpiresDate() {
        return preferences.getInt(EXPIRES_DATE, 0);
    }


    public void destroyData() {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt(EXPIRES_DATE, 0);
        editor.putString(PASSWORD, "");
        editor.apply();
    }
}
