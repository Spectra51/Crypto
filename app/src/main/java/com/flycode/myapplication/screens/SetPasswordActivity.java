package com.flycode.myapplication.screens;

import androidx.appcompat.app.AppCompatActivity;
import androidx.databinding.DataBindingUtil;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import com.flycode.myapplication.R;
import com.flycode.myapplication.databinding.ActivitySetPasswerdBinding;
import com.flycode.myapplication.my_lib.Logger;
import com.flycode.myapplication.my_lib.SCryptoLibrary;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class SetPasswordActivity extends Activity {

    ActivitySetPasswerdBinding mBinding = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mBinding = DataBindingUtil.setContentView(this,R.layout.activity_set_passwerd);
    }

    @Override
    protected void onStart() {
        super.onStart();
        SCryptoLibrary sCryptoLibrary = new SCryptoLibrary(this);
        mBinding.saveBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                    sCryptoLibrary.Init(mBinding.editTextTextPersonName.getText().toString().getBytes());
                    Logger.append("SetPassword Success");

//                    Logger.append("SetPassword Error");
            }
        });
    }
}