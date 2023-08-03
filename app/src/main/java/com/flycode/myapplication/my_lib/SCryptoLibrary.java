package com.flycode.myapplication.my_lib;

import android.content.Context;

import com.flycode.myapplication.inner_lib.GostCrypto;
import com.flycode.myapplication.inner_lib.StorageKeys;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

public class SCryptoLibrary {
    private Context mContext;
    private Storage mStorage;
    private StorageKeys mStorageKeys;

    public SCryptoLibrary(Context appContext) {
        mStorage = new Storage(appContext);
    }

    public int GetStatus() {
        return 0;
    }

    public int Init(byte[] password){
        //1.Задание пароля пользователя. Проверить наличие сохраненного хэш за пароль - если уже есть - возврат с ошибкой 1. Если нет:
        if (!mStorage.getPassword().isEmpty()) {
            return 1;
        }
        //2.сгенерировать с помощью криптопровайдера "соль" - случайное число (32 байта).
        byte[] salt = new byte[4];
        try {
            new GostCrypto().getRandomBytes(salt);
        }catch (NoSuchAlgorithmException | NoSuchProviderException e){
            System.out.println(e.getMessage());
        }
//        mStorage.setSalt(salt);
        //3.рассчитать хэш за пароль и "соль".
        int passwordHash = Objects.hash(password, salt);
        //4.развернуть базу данных (хранилище ключей) - при ошибке - возврат с кодом 2, хэш не сохранять, иначе сохранить хэш с "солью" и дату срока действия (время плюс интервал действия) и вернуть 0.
        try {
            mStorageKeys = new StorageKeys(
                    Arrays.toString(password).toCharArray()
            );
        }catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e){
            System.out.println(e.getMessage());
        }
        int currentDateMSec = new Date().getDate();
        try {
            mStorageKeys.genKeyFromPassword(new byte[]{1, 2, 3, 4, 5, 6, 7});
        }catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e){
            System.out.println(e.getMessage());
        }


        mStorage.setPassword(Arrays.toString(password));
        mStorage.setPasswordHash(Objects.hash(mStorageKeys.getPassword().toString(),mStorage.getSalt()));
        mStorage.setExpiresDate(currentDateMSec);
        mStorage.setSalt(salt);
        Logger.append("DATA SAVED");
        return 0;

    }

    public int DeInit() throws DestroyFailedException {
        mStorageKeys.destroyKeys();
        mStorage.destroyData();
        return 0;
    }

    public int ChangePassword(String opsw,
                              String npsw) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        if (mStorage.getPassword().isEmpty()) {
            return -1;
        }
        String oldPass = Arrays.toString(mStorage.getPassword().getBytes());
        String oldPassCurrent = Arrays.toString(opsw.getBytes());
        int saltHashCode = mStorage.getSalt().hashCode();
        int oldPassHAsh = oldPass.hashCode() + saltHashCode;
        int oldPassHAshCurrent = oldPassCurrent.hashCode() + saltHashCode;
        if (!Objects.equals(oldPassHAsh,oldPassHAshCurrent)){
            return 1;
        }
        //
        mStorageKeys = new StorageKeys(
                npsw.toCharArray()
        );
        byte[] salt = new byte[]{0,0,0,0};
        new GostCrypto().getRandomBytes(salt);
        int currentDateMSec = new Date().getDate();
        mStorage.setSalt(salt);
        mStorage.setPassword(npsw);
        mStorage.setPasswordHash(Objects.hash(mStorageKeys.getPassword().toString(),mStorage.getSalt()));
        mStorage.setExpiresDate(currentDateMSec);
        Logger.append("PASSWORD CHANGED");
        //
        return 0;
    }

    public int CheckPassword(String password) {
        if (password.isEmpty()){
            return 1;
        }
        if (mStorage.getExpiresDate() - new Date().getDate() < 24*60*60*1000){
            return 6;
        }
        if (!Objects.equals(Objects.hash(password,mStorage.getSalt()),mStorage.getPasswordHash())){
            return 1;
        }
        //TODO Save in log
        return 0;
    }

    public int AttachUSIMStorage(byte[] trPassword) {
        return 0;
    }

    public String GetSubscriberId() {
        return "";
    }

    public QKSParamsSCL GetQKSParams() {
        return new QKSParamsSCL();
    }

    public int LoadQKSData(QKSKeysSCL keys,
                           QKSParamsSCL params,
                           String id) {
        return 0;
    }

    public int LoadQKSDataQR(byte[] QRdata) {
        return 0;
    }

    public int SelfTest() {
        return 0;
    }

    public int SaveLog(String path) {
        return 0;
    }

    public int ExportLog(String path) {
        return 0;
    }

    public int StartSession(String id) {
        return 0;
    }

    public int CloseSession(int sid) {
        return 0;
    }

    public int CloseAllSessions() {
        return 0;
    }

    public UserDataSCL EncryptPacket(int sid,
                                     byte[] data) {
        return new UserDataSCL();
    }

    public UserDataSCL DecryptPacket(int sid,
                                     byte[] data) {
        return new UserDataSCL();
    }


}
