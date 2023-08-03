package com.flycode.myapplication.inner_lib;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

public class StorageKeys
{
    GostCrypto gostCrypto = new GostCrypto();
    private char[] password;
    private SecretKey Kpass;
    private SecretKey Kenc;
    private SecretKey Kmac;

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public SecretKey getKpass() {
        return Kpass;
    }

    public void setKpass(SecretKey kpass) {
        Kpass = kpass;
    }

    public SecretKey getKenc() {
        return Kenc;
    }

    public void setKenc(SecretKey kenc) {
        Kenc = kenc;
    }

    public SecretKey getKmac() {
        return Kmac;
    }

    public void setKmac(SecretKey kmac) {
        Kmac = kmac;
    }

    public StorageKeys(char[] passw) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
    {
        this.password = new char[passw.length];
        System.arraycopy(passw, 0, this.password, 0, passw.length);
    }

    public void genKeyFromPassword(byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
    {
        this.Kpass = gostCrypto.magmaPBKDF2(this.password, salt, 2000);
    }

    public void genContainerKeys(byte[] seed) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        //Kdf
        byte[] label = {0x28, (byte) 0xb4, (byte) 0x81, (byte) 0xc5};
        this.Kmac = gostCrypto.magmaKDF_TREE(this.Kpass, 1, label, seed, 512, 1);
        this.Kenc = gostCrypto.magmaKDF_TREE(this.Kpass, 2, label, seed, 512, 1);
    }

    public final byte[] getKeyFromContainer(byte[] container, byte[] iv)
    {
        //Kimp15
        return gostCrypto.magmaKimp15(this.Kenc, this.Kmac, container, iv);
    }

    public final byte[] putKeyToContainer(byte[] key, byte[] iv)
    {
        //Kexp15
        return gostCrypto.magmaKexp15(this.Kenc, this.Kmac, key, iv);
    }

    public void destroyKeys() throws DestroyFailedException {
        this.Kpass.destroy();
        this.Kenc.destroy();
        this.Kmac.destroy();
    }
}
