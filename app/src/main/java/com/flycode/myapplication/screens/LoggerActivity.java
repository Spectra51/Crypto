package com.flycode.myapplication.screens;

import androidx.appcompat.app.AppCompatActivity;
import androidx.databinding.DataBindingUtil;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import com.flycode.myapplication.R;
import com.flycode.myapplication.databinding.ActivityLoggerBinding;
import com.flycode.myapplication.databinding.ActivitySetPasswerdBinding;
import com.flycode.myapplication.my_lib.Logger;

public class LoggerActivity extends Activity {


    ActivityLoggerBinding mBinding = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mBinding = DataBindingUtil.setContentView(this,R.layout.activity_logger);

        mBinding.showLogBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mBinding.editTextTextPersonName2.setText(Logger.exportLog());
            }
        });
        mBinding.clearLogBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Logger.clearLog();
                mBinding.editTextTextPersonName2.setText(Logger.exportLog());
            }
        });
    }
}