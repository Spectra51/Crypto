package com.flycode.myapplication.inner_lib;

import org.apache.commons.codec.binary.Hex;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

//import JCSP.Encryption.SimpleEncryptionMagmaExample;
import ru.CryptoPro.JCP.params.CryptParamsSpec;
import ru.CryptoPro.JCSP.JCSP;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import ru.CryptoPro.JCP.params.KdfTreeDiversKeySpec;

import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore;

import java.math.BigInteger;

public class GostCrypto {

    static final int MAGMA_BLOCK_LEN = 8;

    public final byte[] exportKey(SecretKey key)
    {
        Cipher cipher_wrap = null;
        Cipher cipher_wrap0 = null;

        byte[] key_bytes = new byte[32];

        try {
            cipher_wrap = Cipher.getInstance("GOST28147/ECB/ZeroPadding", "JCSP");
            cipher_wrap0 = Cipher.getInstance("GOST28147/SIMPLE_EXPORT/NoPadding", "JCSP");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
            System.out.println(e.getMessage());
        }

        SecretKey clientAgree = null;

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(JCSP.GOST_CIPHER_NAME, JCSP.PROVIDER_NAME);
            keyGen.init(CryptParamsSpec.getInstance(CryptParamsSpec.Rosstandart_TC26_Z));
            clientAgree = keyGen.generateKey();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            System.out.println(e.getMessage());
        }


        try {
            assert cipher_wrap != null;
            assert cipher_wrap0 != null;

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec sv = new IvParameterSpec(iv);

            cipher_wrap0.init(Cipher.WRAP_MODE, clientAgree, sv);
            byte[] wrappedKey = cipher_wrap0.wrap(key);

            byte[] encrKey = new byte[32];
            System.arraycopy(wrappedKey, 4, encrKey, 0, encrKey.length);
            byte[] macKey = new byte[4];
            System.arraycopy(wrappedKey, 38, macKey, 0, macKey.length);

            cipher_wrap.init(Cipher.DECRYPT_MODE,  clientAgree);
            key_bytes = cipher_wrap.doFinal(encrKey);

            Mac mac = Mac.getInstance("GOST28147", "JCSP");
            mac.init(clientAgree);
            byte[] imit = mac.doFinal(key_bytes);

            boolean b = Arrays.equals(imit, macKey);
            if(!b)
                return new byte[32];

        } catch (IllegalArgumentException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println(e.getMessage());
        }

        return key_bytes;
    }

    public final SecretKey importMagmaKey(byte[] key_bytes)
    {
        byte[] const_wrap_key = {
                0x01,0x20,0x00,0x00,
                0x30,0x66,0x00,0x00, //magma
                (byte) 0xfd,0x51,0x4a,0x37,// magic
                0x1e,0x66,0x00,0x00, //enc_key 28147
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //sync
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //key
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //key
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //key
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //key
                0x00,0x00,0x00,0x00  //imv
                ,0x30, 0x0a, 0x06, 0x08, 0x2a, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x01
        };

        Cipher cipher_wrap = null;
        Cipher cipher_wrap0 = null;

        try {
            cipher_wrap = Cipher.getInstance("GOST28147/ECB/ZeroPadding", "JCSP");
            cipher_wrap0 = Cipher.getInstance("GOST28147/SIMPLE_EXPORT/NoPadding", "JCSP");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
            System.out.println(e.getMessage());
        }

        SecretKey clientAgree = null;
        SecretKey key = null;

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(JCSP.GOST_CIPHER_NAME, JCSP.PROVIDER_NAME);
            keyGen.init(CryptParamsSpec.getInstance(CryptParamsSpec.Rosstandart_TC26_Z));
            clientAgree = keyGen.generateKey();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            System.out.println(e.getMessage());
        }


        try {
            assert cipher_wrap != null;
            assert cipher_wrap0 != null;

            cipher_wrap.init(Cipher.ENCRYPT_MODE,  clientAgree);
            byte[] encrKey = cipher_wrap.doFinal(key_bytes);

            for(int i=0; i<32; i++)
                const_wrap_key[i+24] = encrKey[i];

            Mac mac = Mac.getInstance("GOST28147", "JCSP");
            mac.init(clientAgree);
            byte[] imit = mac.doFinal(key_bytes);

            for(int i=0; i<4; i++)
                const_wrap_key[i+24+32] = imit[i];

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec sv = new IvParameterSpec(iv);

            cipher_wrap0.init(Cipher.UNWRAP_MODE, clientAgree, sv);
            key = (SecretKey) cipher_wrap0.unwrap(const_wrap_key, null, Cipher.SECRET_KEY);

        } catch (IllegalArgumentException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException | BadPaddingException e) {
            System.out.println(e.getMessage());
        }

        return key;
    }

    public final void saveKeyToKS(SecretKey key, String alias, char[] pass) throws KeyStoreException, NoSuchProviderException, CertificateException, IOException, NoSuchAlgorithmException
    {
        KeyStore ks = KeyStore.getInstance("HDIMAGE", "JCSP");
        ks.load(null, null);
        KeyStore.ProtectionParameter params = new KeyStore.PasswordProtection(pass);
        KeyStore.Entry entry = new SecretKeyEntry(key);
        ks.setEntry(alias, entry, params);
    }

    public final void deleteKeyFromKS(String alias) throws KeyStoreException, NoSuchProviderException, CertificateException, IOException, NoSuchAlgorithmException
    {
        KeyStore ks = KeyStore.getInstance("HDIMAGE", "JCSP");
        ks.load(null, null);
        ks.deleteEntry(alias);
    }

    public final SecretKey getKeyFromKS(String alias, char[] pass) throws KeyStoreException, NoSuchProviderException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException
    {
        KeyStore ks = KeyStore.getInstance("HDIMAGE", "JCSP");
        ks.load(null, null);
        KeyStore.ProtectionParameter params = new KeyStore.PasswordProtection(pass);
        //KeyStore.Entry entry = ks.getEntry(alias, params);
        SecretKeyEntry entry = (SecretKeyEntry) ks.getEntry(alias, params);
        return entry.getSecretKey();
        //return (SecretKey) ks.getKey(alias, pass);
    }

    public final byte[] magmaEncryptECB(SecretKey key, byte[] input)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaEncryptECB()] Error: key algorithm != GOST3412_2015_M");
            return new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
        }

        int dop_len = MAGMA_BLOCK_LEN - (input.length % MAGMA_BLOCK_LEN);
        if(dop_len == 8) dop_len = 0;
        int input_len = input.length + dop_len;
        byte[] cipherText = new byte[input_len];
        byte[] inputText = new byte[input_len];
        System.arraycopy(input, 0, inputText, 0, input.length);

        if(dop_len > 0) {
            inputText[input.length] = (byte)0x80;
            for(int i=input.length+1; i<input_len; i++)
                inputText[i] = (byte)0x00;
        }

        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance("GOST3412_2015_M/ECB/ZeroPadding", "JCSP");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            try {
                cipherText = cipher.doFinal(inputText);

            } catch (ClassCastException | BadPaddingException | IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println(e.getMessage());
        }
        return cipherText;
    }

    public final byte[] magmaDecryptECB(SecretKey key, byte[] input, int length)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaDecryptECB()] Error: key algorithm != GOST3412_2015_M");
            return new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
        }

        byte[] outputText = new byte[input.length];
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance("GOST3412_2015_M/ECB/ZeroPadding", "JCSP");
            cipher.init(Cipher.DECRYPT_MODE, key);

            try {
                outputText = cipher.doFinal(input);

            } catch (ClassCastException | BadPaddingException | IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println(e.getMessage());
        }

        byte[] output = new byte[length];
        System.arraycopy(outputText, 0, output, 0, length);

        return output;
    }

    public final byte[] magmaEncryptCTR(SecretKey key, byte[] input, byte[] iv)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaEncryptCTR()] Error: key algorithm != GOST3412_2015_M");
            return new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
        }

        byte[] iv_tmp = new byte[8];
        System.arraycopy(iv, 0, iv_tmp, 0, iv.length);

        byte[] cipherText = new byte[input.length];
        Cipher cipher = null;
        IvParameterSpec sv = new IvParameterSpec(iv_tmp);

        try {
            cipher = Cipher.getInstance("GOST3412_2015_M/CTR/NoPadding", "JCSP");
            cipher.init(Cipher.ENCRYPT_MODE, key, sv);

            try {
                cipherText = cipher.doFinal(input);

            } catch (ClassCastException | BadPaddingException | IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println(e.getMessage());
        }
        return cipherText;
    }

    public final byte[] magmaDecryptCTR(SecretKey key, byte[] input, byte[] iv)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaDecryptCTR()] Error: key algorithm != GOST3412_2015_M");
            return new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
        }

        byte[] iv_tmp = new byte[8];
        System.arraycopy(iv, 0, iv_tmp, 0, iv.length);

        byte[] cipherText = new byte[input.length];
        Cipher cipher = null;
        IvParameterSpec sv = new IvParameterSpec(iv_tmp);

        try {
            cipher = Cipher.getInstance("GOST3412_2015_M/CTR/NoPadding", "JCSP");
            cipher.init(Cipher.DECRYPT_MODE, key, sv);

            try {
                cipherText = cipher.doFinal(input);

            } catch (ClassCastException | BadPaddingException | IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println(e.getMessage());
        }
        return cipherText;
    }

    public final byte[] magmaMac(SecretKey key, byte[] input)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaMac()] Error: key algorithm != GOST3412_2015_M");
            return new byte[]{0, 0, 0, 0};
        }

        byte[] imit = new byte[4];

        try {
            Mac mac = Mac.getInstance("GOST3412_2015_M", "JCSP");
            mac.init(key);
            imit = mac.doFinal(input);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println(e.getMessage());
        }

        return imit;
    }

    public final byte[] magmaMac8(SecretKey key, byte[] input)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaMac()] Error: key algorithm != GOST3412_2015_M");
            return new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
        }

        int dop_len = MAGMA_BLOCK_LEN - (input.length % MAGMA_BLOCK_LEN);
        if(dop_len == 8) dop_len = 0;
        int input_len = input.length + dop_len;
        byte[] cipherText = new byte[8];
        byte[] inputText = new byte[input_len];
        System.arraycopy(input, 0, inputText, 0, input.length);

        if(dop_len > 0) {
            inputText[input.length] = (byte)0x80;
            for(int i=input.length+1; i<input_len; i++)
                inputText[i] = (byte)0x00;
        }

        byte[] r0 = {0, 0, 0, 0, 0, 0, 0, 0};

        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance("GOST3412_2015_M/ECB/ZeroPadding", "JCSP");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            try {
                byte[] re = cipher.doFinal(r0);
                int msb = re[0] & 0x80;
                byte k1[] = new BigInteger(re).shiftLeft(1).toByteArray();
                if(msb != 0)
                {
                    k1[k1.length - 1] ^= 0x1b;
                }
                msb = k1[k1.length - 8] & 0x80;
                byte k2[] = new BigInteger(k1).shiftLeft(1).toByteArray();
                if(msb != 0)
                {
                    k2[k2.length - 1] ^= 0x1b;
                }

                byte[] c0 = {0, 0, 0, 0, 0, 0, 0, 0};

                for(int i=0; i<inputText.length - 8; i+=8)
                {
                    for (int j1 = 0, j2 = i; j1 < 8; j1++, j2++)
                        c0[j1] ^= inputText[j2];

                    byte[] ci = cipher.doFinal(c0);
                    System.arraycopy(ci, 0, c0, 0, 8);
                }
                if(dop_len == 0)
                {
                    for (int j1 = 0, j2 = inputText.length - 8; j1 < 8; j1++, j2++)
                        c0[j1] = (byte) (c0[j1] ^ inputText[j2] ^ k1[k1.length - 8 + j1]);
                }
                else
                {
                    for (int j1 = 0, j2 = inputText.length - 8; j1 < 8; j1++, j2++)
                        c0[j1] = (byte) (c0[j1] ^ inputText[j2] ^ k2[k2.length - 8 + j1]);
                }

                return cipher.doFinal(c0);

            } catch (ClassCastException | BadPaddingException | IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
                return new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println(e.getMessage());
            return new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
        }
    }

    public final boolean magmaCheckMac8(SecretKey key, byte[] input, byte[] input_imit)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaMac()] Error: key algorithm != GOST3412_2015_M");
            return false;
        }

        byte[] imit = magmaMac8(key, input);
        return Arrays.equals(imit, input_imit);
    }

    public final boolean magmaCheckMac(SecretKey key, byte[] input, byte[] input_imit)
    {
        String kalg = key.getAlgorithm();
        if (!Objects.equals(kalg, "GOST3412_2015_M")) {
            System.out.println("[GostCrypto.magmaMac()] Error: key algorithm != GOST3412_2015_M");
            return false;
        }

        byte[] imit = new byte[4];

        try {
            Mac mac = Mac.getInstance("GOST3412_2015_M", "JCSP");
            mac.init(key);
            imit = mac.doFinal(input);

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println(e.getMessage());
        }
        return Arrays.equals(imit, input_imit);
    }

    public final byte[] hash256(byte[] input)
    {
        byte[] hash = new byte[32];

        try {
            MessageDigest md = MessageDigest.getInstance("GOST3411_2012_256", "JCSP");
            hash = md.digest(input);
        } catch(NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println(e.getMessage());
        }

        return hash;
    }

    public final boolean checkFileHash(String filename, byte[] inp_hash)
    {
        try {
            FileInputStream f = new FileInputStream(filename);
            byte[] input = new byte[f.available()];
            f.read(input, 0, f.available());
            MessageDigest md = MessageDigest.getInstance("GOST3411_2012_256", "JCSP");
            byte[] hash = md.digest(input);
            String h = Hex.encodeHexString(hash);
            return Arrays.equals(hash, inp_hash);
        } catch(NoSuchAlgorithmException | NoSuchProviderException | IOException e) {
            System.out.println(e.getMessage());
        }

        return false;
    }

    public final SecretKey magmaKDF_TREE(SecretKey key, int idx, byte[] label, byte[] seed, int L, int R) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("GOST3412_2015_M", "JCSP");
        KdfTreeDiversKeySpec diversKeySpec = new KdfTreeDiversKeySpec(key, label, idx, seed, L, R);
        return secretKeyFactory.generateSecret(diversKeySpec);
    }

    public final SecretKey magmaPBKDF2(char[] password, byte[] salt, int iteration_count) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
    {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("GOST3412_2015_M", "JCSP");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iteration_count, 256);
        return secretKeyFactory.generateSecret(pbeKeySpec);
    }

    public final byte[] magmaKexp15(SecretKey kenc, SecretKey kmac, byte[] key_bytes, byte[] iv)
    {
        byte[] buf_to_mac = new byte[key_bytes.length + iv.length];
        System.arraycopy(iv, 0, buf_to_mac, 0, iv.length);
        System.arraycopy(key_bytes, 0, buf_to_mac, iv.length, key_bytes.length);

        byte[] keymac = magmaMac8(kmac, buf_to_mac);

        byte[] cipherText = new byte[key_bytes.length + keymac.length];
        Cipher cipher = null;
        IvParameterSpec sv = new IvParameterSpec(iv);

        byte[] kexp_enc = new byte[key_bytes.length + keymac.length];
        System.arraycopy(key_bytes, 0, kexp_enc, 0, key_bytes.length);
        System.arraycopy(keymac, 0, kexp_enc, key_bytes.length, keymac.length);

        try {
            cipher = Cipher.getInstance("GOST3412_2015_M/CTR_ACPKM/NoPadding", "JCSP");
            cipher.init(Cipher.ENCRYPT_MODE, kenc, sv);
            try {
                cipherText = cipher.doFinal(kexp_enc);

            } catch (ClassCastException | BadPaddingException | IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println(e.getMessage());
        }
        return cipherText;
    }

    public final byte[] magmaKimp15(SecretKey kenc, SecretKey kmac, byte[] kexp_bytes, byte[] iv)
    {
        byte[] key_bytes = new byte[kexp_bytes.length - 8];
        Cipher cipher = null;
        IvParameterSpec sv = new IvParameterSpec(iv);

        try {
            cipher = Cipher.getInstance("GOST3412_2015_M/CTR_ACPKM/NoPadding", "JCSP");
            cipher.init(Cipher.DECRYPT_MODE, kenc, sv);

            try {
                byte[] keymac = cipher.doFinal(kexp_bytes);

                byte[] buf_to_mac = new byte[key_bytes.length + iv.length];
                System.arraycopy(iv, 0, buf_to_mac, 0, iv.length);
                System.arraycopy(keymac, 0, buf_to_mac, iv.length, key_bytes.length);

                byte[] mac = new byte[8];
                System.arraycopy(keymac, key_bytes.length, mac, 0, mac.length);

                if(magmaCheckMac8(kmac, buf_to_mac, mac))
                {
                    System.arraycopy(keymac, 0, key_bytes, 0, key_bytes.length);
                }
                else
                {
                    System.out.println("[GostCrypto.magmaKimp15()] Error: magmaCheckMac8()");
                }

            } catch (ClassCastException | BadPaddingException | IllegalBlockSizeException e) {
                System.out.println(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println(e.getMessage());
        }
        return key_bytes;
    }

    public final void getRandomBytes(byte[] buffer) throws NoSuchAlgorithmException, NoSuchProviderException
    {
//        JCSP provider = new JCSP();
        SecureRandom rnd = new SecureRandom();//.getInstance("CPRandom");//TODO//, "JCSP");
        rnd.nextBytes(buffer);
    }
}
