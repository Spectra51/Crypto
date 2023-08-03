package com.flycode.myapplication;

import androidx.appcompat.app.AppCompatActivity;
import androidx.databinding.DataBindingUtil;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import com.flycode.myapplication.databinding.ActivityMainBinding;
import com.flycode.myapplication.databinding.ActivitySetPasswerdBinding;
import com.flycode.myapplication.my_lib.Logger;
import com.flycode.myapplication.screens.ChangePasswordActivity;
import com.flycode.myapplication.screens.LoggerActivity;
import com.flycode.myapplication.screens.SetPasswordActivity;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Enumeration;

import dalvik.system.DexFile;

public class MainActivity extends AppCompatActivity {


    ActivityMainBinding mBinding = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mBinding = DataBindingUtil.setContentView(this, R.layout.activity_main);
        Context context = this;
        mBinding.loggerBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(new Intent(context, LoggerActivity.class));
            }
        });
        mBinding.setPasswordBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(new Intent(context, SetPasswordActivity.class));
            }
        });
        mBinding.changePasswordBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(new Intent(context, ChangePasswordActivity.class));
            }
        });
        init();
    }

    private void init() {
        Logger.init(this.getFilesDir().getPath() + "/log.txt");
    }
//    public void checkIntegrity() throws Exception{
//        CSPProviderInterface providerInfo = CSPConfig.INSTANCE.getCSPProviderInfo();
//        IntegrityInterface integrity = providerInfo.getIntegrity();
//        int result = integrity.check(true);
//        if (result != CSPIntegrityConstants.CHECK_INTEGRITY_SUCCESS) {
//            throw new Exception("Integrity corrupted.");
//        }
//    }
}