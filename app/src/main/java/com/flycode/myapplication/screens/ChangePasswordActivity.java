package com.flycode.myapplication.screens;

import androidx.appcompat.app.AppCompatActivity;
import androidx.databinding.DataBindingUtil;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import com.flycode.myapplication.R;
import com.flycode.myapplication.databinding.ActivityChangePasswordBinding;
import com.flycode.myapplication.databinding.ActivityLoggerBinding;
import com.flycode.myapplication.my_lib.Logger;
import com.flycode.myapplication.my_lib.SCryptoLibrary;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class ChangePasswordActivity extends AppCompatActivity {

    ActivityChangePasswordBinding mBinding = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mBinding = DataBindingUtil.setContentView(this,R.layout.activity_change_password);

        SCryptoLibrary sCryptoLibrary = new SCryptoLibrary(this);
        mBinding.changePasswordBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    sCryptoLibrary.ChangePassword(mBinding.editTextTextPersonName4.getText().toString(),
                            mBinding.editTextTextPersonName3.getText().toString());
                } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
                    Logger.append("CHANGE PASSWORD ERROR");
                }
            }
        });
    }
}