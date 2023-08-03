package com.flycode.myapplication.inner_lib;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;

public class Protoqa
{
    //--------CRISP----------
    /*static class CRISP_KeyID
    {
        public static final byte Const = (byte)0xa8;
        public byte[] SenderID;
        public byte[] RecipientID;
        public byte[] KeyCounter;
        public static final int SR_ID_LEN = 16;
        public static final int KeyCounter_LEN = 8;
    };*/

    static final int CRISP_HEADER_LEN = 50;
    static final int APP_HEADER_LEN = 47;
    static final int APP_REQ_LEN = 25;
    static final int APP_RESP_LEN = 61;

    static final int ID_LEN = 16;
    byte[] AbonentID;
    byte[] SKKID;

    SecretKey AbonentKey;
    SecretKey SKKKey;
    SecretKey KexpKey;
    BigInteger KeyCtrA;
    BigInteger KeyCtrB;
    //BigInteger KeyCtrSKK;
    //byte[] KeyCtrA_b;
    //byte[] KeyCtrSKK_b;
    byte[] AbonentKeyID;
    byte[] SKKKeyID;
    static final int Key_ID_LEN = 41;

    BigInteger SeqNumA;
    BigInteger SeqNumSKK;
    //BigInteger SessionIdA;
    BigInteger SessionIdSKK;

    long ProtoqaImitErrors;
    static final long ProtoqaImitErrorsMAX = 100;

    int seed_flag;
    int skk_flag;

    BigInteger SEQ_NUM_MAX = new BigInteger("ffffffffffff", 16);
    BigInteger SEQ_NUM_MAX_100 = new BigInteger("900");
    BigInteger SEQ_NUM_MAX_101 = new BigInteger("899");
    BigInteger SESSION_ID_MAX = new BigInteger("ffffffff", 16);

    GostCrypto gostCrypto = new GostCrypto();

    static class CRISP_msg
    {
        public byte[] ExternalKeyIdFlagAndVersion;
        public final byte CS = (byte)0x01;
        public byte[] KeyID;
        public byte[] SeqNum;
        public final int FLAG_LEN = 2;
        public final int KeyID_LEN = 41;
        public final int SeqNum_LEN = 6;
    };

    CRISP_msg crisp_header = new CRISP_msg();

    Protoqa(byte[] abonent_id, byte[] skk_id, byte[] abonent_key, byte[] skk_key, byte[] kexp_key, BigInteger key_ctr,
            BigInteger seq_numA, BigInteger seq_numSKK, BigInteger session_id, long imit_errors)
    {
        AbonentID = abonent_id;
        SKKID = skk_id;
        KeyCtrA = key_ctr;
        //KeyCtrSKK = skk_key_ctr;

        AbonentKeyID = new byte[Key_ID_LEN];
        SKKKeyID = new byte[Key_ID_LEN];

        AbonentKeyID[0] = (byte) 0xa8;
        System.arraycopy(AbonentID, 0, AbonentKeyID, 1, 16);
        System.arraycopy(SKKID, 0, AbonentKeyID, 1 + 16, 16);
        System.arraycopy(KeyCtrA.toByteArray(), 0, AbonentKeyID, 1 + 16*2 + 8 - KeyCtrA.toByteArray().length, KeyCtrA.toByteArray().length);

        SKKKeyID[0] = (byte) 0xa8;
        System.arraycopy(SKKID, 0, SKKKeyID, 1, 16);
        System.arraycopy(AbonentID, 0, SKKKeyID, 1 + 16, 16);
        //System.arraycopy(KeyCtrSKK.toByteArray(), 0, SKKKeyID, 1 + 16*2 + 8 - KeyCtrSKK.toByteArray().length, KeyCtrSKK.toByteArray().length);
        System.arraycopy(KeyCtrA.toByteArray(), 0, SKKKeyID, 1 + 16*2 + 8 - KeyCtrA.toByteArray().length, KeyCtrA.toByteArray().length);

        AbonentKey = gostCrypto.importMagmaKey(abonent_key);
        SKKKey = gostCrypto.importMagmaKey(skk_key);
        KexpKey = gostCrypto.importMagmaKey(kexp_key);

        SeqNumA = seq_numA;
        SeqNumSKK = seq_numSKK;
        SessionIdSKK = session_id;

        ProtoqaImitErrors = imit_errors;
        seed_flag = 0;
        skk_flag = 1;

        crisp_header.ExternalKeyIdFlagAndVersion = new byte[crisp_header.FLAG_LEN];
        crisp_header.KeyID = new byte[crisp_header.KeyID_LEN];
        crisp_header.SeqNum = new byte[crisp_header.SeqNum_LEN];
    }

    Protoqa(byte[] abonentA_id, byte[] abonentB_id, byte[] abonentA_key, byte[] abonentB_key, BigInteger key_ctr_A, BigInteger key_ctr_B,
            BigInteger seq_numA, BigInteger seq_numB, long imit_errors)
    {
        AbonentID = abonentA_id;
        SKKID = abonentB_id;
        //KeyCtrA = key_ctr;
        KeyCtrA = key_ctr_A;
        KeyCtrB = key_ctr_B;
        //KeyCtrSKK = skk_key_ctr;

        AbonentKeyID = new byte[Key_ID_LEN];
        SKKKeyID = new byte[Key_ID_LEN];

        AbonentKeyID[0] = (byte) 0xa8;
        System.arraycopy(AbonentID, 0, AbonentKeyID, 1, 16);
        System.arraycopy(SKKID, 0, AbonentKeyID, 1 + 16, 16);
        System.arraycopy(KeyCtrA.toByteArray(), 0, AbonentKeyID, 1 + 16*2 + 8 - KeyCtrA.toByteArray().length, KeyCtrA.toByteArray().length);

        SKKKeyID[0] = (byte) 0xa8;
        System.arraycopy(SKKID, 0, SKKKeyID, 1, 16);
        System.arraycopy(AbonentID, 0, SKKKeyID, 1 + 16, 16);
        //System.arraycopy(KeyCtrSKK.toByteArray(), 0, SKKKeyID, 1 + 16*2 + 8 - KeyCtrSKK.toByteArray().length, KeyCtrSKK.toByteArray().length);
        //System.arraycopy(KeyCtrA.toByteArray(), 0, SKKKeyID, 1 + 16*2 + 8 - KeyCtrA.toByteArray().length, KeyCtrA.toByteArray().length);
        System.arraycopy(KeyCtrB.toByteArray(), 0, SKKKeyID, 1 + 16*2 + 8 - KeyCtrB.toByteArray().length, KeyCtrB.toByteArray().length);

        AbonentKey = gostCrypto.importMagmaKey(abonentA_key);
        SKKKey = gostCrypto.importMagmaKey(abonentB_key);

        SeqNumA = seq_numA;
        SeqNumSKK = seq_numB;

        ProtoqaImitErrors = imit_errors;
        seed_flag = 0;
        skk_flag = 0;

        crisp_header.ExternalKeyIdFlagAndVersion = new byte[crisp_header.FLAG_LEN];
        crisp_header.KeyID = new byte[crisp_header.KeyID_LEN];
        crisp_header.SeqNum = new byte[crisp_header.SeqNum_LEN];
    }

    private void CRISP_form_keys(SecretKey key, byte[] kenc, byte[] kmac, byte[] send_id, BigInteger seq_num)
    {
        byte[] label = { 'm', 'a', 'c', 'e', 'n', 'c' };
        byte aL = 6;
        byte[] SN = new byte[5];
        byte CS = 1;
        byte[] cL = { 0x00, 0x16 };
        byte[] oL = { 0x02, 0x00 };

        byte[] sn_tmp = seq_num.shiftRight(5).toByteArray();
        if(sn_tmp.length >= SN.length) {
            System.arraycopy(sn_tmp, sn_tmp.length - SN.length, SN, 0, SN.length);
        }
        else {
            for (int i = sn_tmp.length - 1, j = SN.length - 1; i >= 0; i--, j--)
                SN[j] = sn_tmp[i];
        }

        byte[] data = new byte[34];
        System.arraycopy(label, 0, data, 1, label.length);
        data[1 + label.length] = aL;
        System.arraycopy(SN, 0, data, 2 + label.length, SN.length);
        System.arraycopy(send_id, 0, data, 2 + label.length + SN.length, send_id.length);
        data[2 + label.length + SN.length + send_id.length] = CS;
        System.arraycopy(cL, 0, data, 3 + label.length + SN.length + send_id.length, cL.length);
        System.arraycopy(oL, 0, data, 3 + label.length + SN.length + send_id.length + cL.length, oL.length);

        //String hexwrap = Hex.encodeHexString(data);

        for(int i=0; i<4; i++)
        {
            data[0] = (byte) (i+1);
            byte[] Ki = gostCrypto.magmaMac8(key, data);
            System.arraycopy(Ki, 0, kmac, i * 8, Ki.length);
        }
        for(int i=0, j=5; i<4; i++, j++)
        {
            data[0] = (byte) (j);
            byte[] Ki = gostCrypto.magmaMac8(key, data);
            System.arraycopy(Ki, 0, kenc, i * 8, Ki.length);
        }

    }

    public final byte[] CRISP_encrypt_msg(byte[] payload_data)
    {
        if(this.SeqNumA.equals(SEQ_NUM_MAX))
        {
            System.out.println("[Protoqa.CRISP_encrypt_msg()] Error: SeqNumA == SEQ_NUM_MAX");
            return new byte[1];
        }
        this.SeqNumA = this.SeqNumA.add(new BigInteger("1"));
        if(this.skk_flag == 1)
        {
            if(this.SeqNumA.compareTo(this.SEQ_NUM_MAX_100) > 0)
            {
                if(this.seed_flag == 1)
                {
                    this.seed_flag = 0;
                }
                else
                {
                    System.out.println("[Protoqa.CRISP_decrypt_msg()] Error: SeqNumA >= SeqNumMax - 100 & seed_flag = 0");
                    return new byte[2];
                }
            }
        }

        byte[] msg = new byte[CRISP_HEADER_LEN + payload_data.length + 4];
        System.arraycopy(this.AbonentKeyID, 0, this.crisp_header.KeyID, 0, this.AbonentKeyID.length);
        byte[] seq_num_tmp = this.SeqNumA.toByteArray();
        System.arraycopy(seq_num_tmp, 0, this.crisp_header.SeqNum, this.crisp_header.SeqNum_LEN - seq_num_tmp.length, seq_num_tmp.length);

        byte[] kenc_b = new byte[32];
        byte[] kmac_b = new byte[32];
        CRISP_form_keys(this.AbonentKey, kenc_b, kmac_b, this.AbonentID, this.SeqNumA);
        SecretKey kenc = gostCrypto.importMagmaKey(kenc_b);
        SecretKey kmac = gostCrypto.importMagmaKey(kmac_b);

        byte[] iv = new byte[4];
        System.arraycopy(this.crisp_header.SeqNum, 2, iv, 0, iv.length);
        byte[] payload_ciph = gostCrypto.magmaEncryptCTR(kenc, payload_data, iv);

        System.arraycopy(this.crisp_header.ExternalKeyIdFlagAndVersion, 0, msg, 0, this.crisp_header.FLAG_LEN);
        msg[this.crisp_header.FLAG_LEN] = this.crisp_header.CS;
        System.arraycopy(this.crisp_header.KeyID, 0, msg, 1 + this.crisp_header.FLAG_LEN, this.crisp_header.KeyID_LEN);
        System.arraycopy(this.crisp_header.SeqNum, 0, msg, 1 + this.crisp_header.FLAG_LEN + this.crisp_header.KeyID_LEN, this.crisp_header.SeqNum_LEN);
        System.arraycopy(payload_ciph, 0, msg, 1 + this.crisp_header.FLAG_LEN + this.crisp_header.KeyID_LEN + this.crisp_header.SeqNum_LEN, payload_ciph.length);

        byte[] mac_data = new byte[CRISP_HEADER_LEN + payload_data.length];
        System.arraycopy(msg, 0, mac_data, 0, mac_data.length);
        byte[] ICV = gostCrypto.magmaMac(kmac, mac_data);
        System.arraycopy(ICV, 0, msg, msg.length - ICV.length, ICV.length);

        return msg;
    }

    public final byte[] CRISP_decrypt_msg(byte[] msg)
    {
        if(msg[0] != 0 || msg[1] != 0)
        {
            System.out.println("[Protoqa.CRISP_decrypt_msg()] Error: - ExternalKeyIdFlagAndVersion != 0");
            return new byte[0];
        }
        if(msg[2] != 1)
        {
            System.out.println("[Protoqa.CRISP_decrypt_msg()] Error: - CS != 1");
            return new byte[0];
        }

        System.arraycopy(msg, this.crisp_header.FLAG_LEN + 1, this.crisp_header.KeyID, 0, this.crisp_header.KeyID_LEN);
        if (!Arrays.equals(this.crisp_header.KeyID, this.SKKKeyID)) {
            System.out.println("[Protoqa.CRISP_decrypt_msg()] Error: wrong KeyID");
            return new byte[0];
        }

        this.crisp_header.SeqNum = new byte[this.crisp_header.SeqNum_LEN];
        System.arraycopy(msg, this.crisp_header.FLAG_LEN + 1 + this.crisp_header.KeyID_LEN, this.crisp_header.SeqNum, 0, this.crisp_header.SeqNum_LEN);

        BigInteger seq_num = new BigInteger(this.crisp_header.SeqNum);
        if(seq_num.compareTo(this.SeqNumSKK) < 1)
        {
            System.out.println("[Protoqa.CRISP_decrypt_msg()] Error: seq_num <= seq_num_svd");
            return new byte[0];
        }

        byte[] kenc_b = new byte[32];
        byte[] kmac_b = new byte[32];
        CRISP_form_keys(this.SKKKey, kenc_b, kmac_b, this.SKKID, seq_num);
        SecretKey kenc = gostCrypto.importMagmaKey(kenc_b);
        SecretKey kmac = gostCrypto.importMagmaKey(kmac_b);

        byte[] mac_data = new byte[msg.length - 4];
        System.arraycopy(msg, 0, mac_data, 0, mac_data.length);
        byte[] ICV_msg = new byte[4];
        System.arraycopy(msg, mac_data.length, ICV_msg, 0, 4);
        if(!gostCrypto.magmaCheckMac(kmac, mac_data, ICV_msg))
        {
            System.out.println("[Protoqa.CRISP_decrypt_msg()] Error: check ICV");
            ProtoqaImitErrors += 1;
            if (ProtoqaImitErrors == ProtoqaImitErrorsMAX)
            {
                if(this.skk_flag == 1)
                    this.SeqNumA = SEQ_NUM_MAX_101;
                System.out.println("[Protoqa.CRISP_decrypt_msg()] [!!!] ProtoqaImitErrors == ProtoqaImitErrorsMAX");
                return new byte[1];
            }
            return new byte[0];
        }

        this.SeqNumSKK = seq_num;
        byte[] iv = new byte[4];
        System.arraycopy(this.crisp_header.SeqNum, 2, iv, 0, iv.length);
        byte[] payload_ciph = new byte[msg.length - 4 - CRISP_HEADER_LEN];
        System.arraycopy(msg, CRISP_HEADER_LEN, payload_ciph, 0, payload_ciph.length);
        byte[] payload_data = gostCrypto.magmaDecryptCTR(kenc, payload_ciph, iv);
        System.arraycopy(payload_data, 0, msg, CRISP_HEADER_LEN, payload_data.length);

        return payload_data;
    }
    //-----------------------

    private byte[] Protoqa_form_req(byte[] pair_id, byte[] keylabel)
    {
        byte[] req = new byte[APP_HEADER_LEN + APP_REQ_LEN + keylabel.length];

        System.arraycopy(this.AbonentID, 0, req, 1, ID_LEN);
        System.arraycopy(this.SKKID, 0, req, 1 + ID_LEN, ID_LEN);
        System.arraycopy(this.SessionIdSKK.toByteArray(), 0, req, 1 + 2*ID_LEN + 4 - this.SessionIdSKK.toByteArray().length, this.SessionIdSKK.toByteArray().length);
        req[1 + 2*ID_LEN + 4] = 4;

        System.arraycopy(pair_id, 0, req, APP_HEADER_LEN, ID_LEN);
        req[22] = 0x20;
        req[23] = 0x02;
        req[24] = (byte) keylabel.length;
        System.arraycopy(keylabel, 0, req, APP_HEADER_LEN + APP_REQ_LEN, keylabel.length);

        return req;
    }

    public final byte[] makeSKKReqKeyA(byte[] Abonent_B_ID)
    {
        byte[] keylabel = new byte[32];
        System.arraycopy(this.AbonentID, 0, keylabel, 0, ID_LEN);
        System.arraycopy(Abonent_B_ID, 0, keylabel, ID_LEN, ID_LEN);
        byte[] payload_data = Protoqa_form_req(Abonent_B_ID, keylabel);

        if(this.SessionIdSKK.equals(SESSION_ID_MAX))
            this.SessionIdSKK = new BigInteger("0");
        else
            this.SessionIdSKK = this.SessionIdSKK.add(new BigInteger("1"));

        return CRISP_encrypt_msg(payload_data);
    }

    public final byte[] makeSKKReqKeyB(byte[] Abonent_B_ID)
    {
        byte[] keylabel = new byte[32];
        System.arraycopy(Abonent_B_ID, 0, keylabel, 0, ID_LEN);
        System.arraycopy(this.AbonentID, 0, keylabel, ID_LEN, ID_LEN);
        byte[] payload_data = Protoqa_form_req(Abonent_B_ID, keylabel);

        if(this.SessionIdSKK.equals(SESSION_ID_MAX))
            this.SessionIdSKK = new BigInteger("0");
        else
            this.SessionIdSKK = this.SessionIdSKK.add(new BigInteger("1"));

        return CRISP_encrypt_msg(payload_data);
    }

    public final byte[] makeSKKReqSeed()
    {
        byte[] keylabel = new byte[0];
        byte[] payload_data = Protoqa_form_req(this.SKKID, keylabel);

        if(this.SessionIdSKK.equals(SESSION_ID_MAX))
            this.SessionIdSKK = new BigInteger("0");
        else
            this.SessionIdSKK = this.SessionIdSKK.add(new BigInteger("1"));

        this.seed_flag = 1;
        return CRISP_encrypt_msg(payload_data);
    }

    //-----------------------

    private void Protoqa_form_kexp15_keys(SecretKey key, byte[] kenc, byte[] kmac, byte[] send_id, BigInteger seq_num)
    {
        byte[] label = { 'k', 'e', 'x', 'p', '1', '5' };
        byte aL = 6;
        byte[] SN = new byte[5];
        byte CS = 1;
        byte[] cL = { 0x00, 0x16 };
        byte[] oL = { 0x02, 0x00 };

        byte[] sn_tmp = seq_num.shiftRight(5).toByteArray();
        if(sn_tmp.length >= SN.length) {
            System.arraycopy(sn_tmp, sn_tmp.length - SN.length, SN, 0, SN.length);
        }
        else {
            for (int i = sn_tmp.length - 1, j = SN.length - 1; i >= 0; i--, j--)
                SN[j] = sn_tmp[i];
        }

        byte[] data = new byte[34];
        System.arraycopy(label, 0, data, 1, label.length);
        data[1 + label.length] = aL;
        System.arraycopy(SN, 0, data, 2 + label.length, SN.length);
        System.arraycopy(send_id, 0, data, 2 + label.length + SN.length, send_id.length);
        data[2 + label.length + SN.length + send_id.length] = CS;
        System.arraycopy(cL, 0, data, 3 + label.length + SN.length + send_id.length, cL.length);
        System.arraycopy(oL, 0, data, 3 + label.length + SN.length + send_id.length + cL.length, oL.length);

        //String hexwrap = Hex.encodeHexString(data);

        for(int i=0; i<4; i++)
        {
            data[0] = (byte) (i+1);
            byte[] Ki = gostCrypto.magmaMac8(key, data);
            System.arraycopy(Ki, 0, kmac, i * 8, Ki.length);
        }
        for(int i=0, j=5; i<4; i++, j++)
        {
            data[0] = (byte) (j);
            byte[] Ki = gostCrypto.magmaMac8(key, data);
            System.arraycopy(Ki, 0, kenc, i * 8, Ki.length);
        }
    }

    public final byte[] Protoqa_kdf(SecretKey key, byte[] seed) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        byte[] label = {0x44, 0x6f, 0x67, 0x65};
        SecretKey k = gostCrypto.magmaKDF_TREE(key, 1, label, seed, 256, 1);
        return gostCrypto.exportKey(k);
    }

    public final byte[] decryptSKKResp(byte[] msg, byte[] q_ctr) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
    {
        byte[] decr_msg = CRISP_decrypt_msg(msg);
        if (decr_msg.length == 0 || decr_msg.length == 1)
        {
            System.out.println("[Protoqa.decryptSKKResp()] Error: CRISP_decrypt_msg");
            return decr_msg;
        }

        //проверить хэдер и посмотреть, пришел ответ или код ошибки

        if(decr_msg[0] != 0)
        {
            System.out.println("[Protoqa.decryptSKKResp()] Error: resp_header.Ver != 0x00");
            return new byte[0];
        }
        byte[] id = new byte[16];
        System.arraycopy(decr_msg, 1, id, 0, id.length);
        if (!Arrays.equals(id, this.SKKID)) {
            System.out.println("[Protoqa.decryptSKKResp()] Error: resp_header.SndID != SKKID");
            return new byte[0];
        }
        System.arraycopy(decr_msg,  1 + id.length, id, 0, id.length);
        if (!Arrays.equals(id, this.AbonentID)) {
            System.out.println("[Protoqa.decryptSKKResp()] Error: resp_header.RcpID != AbonentID");
            return new byte[0];
        }
        byte[] sid_b = new byte[4];
        System.arraycopy(decr_msg, 1 + id.length*2, sid_b, 0, sid_b.length);
        BigInteger sid = new BigInteger(sid_b);
        sid = sid.add(new BigInteger("1"));
        if(!sid.equals(this.SessionIdSKK))
        {
            System.out.println("[Protoqa.decryptSKKResp()] Error: received sessionID != sent sessionID");
            return new byte[0];
        }

        System.arraycopy(decr_msg, APP_HEADER_LEN + 17 + 32, q_ctr, 0, 8);

        if(msg[1 + 16*2 + 4] == 4)
        {
            if(msg[1 + 16*2 + 4 + 1] == 2)
            {
                byte[] key_cont = new byte[32 + 20];
                byte[] iv = new byte[4];
                byte[] key_wrap_id = new byte[8];
                byte[] kexp = new byte[32 + 8];

                System.arraycopy(decr_msg, APP_HEADER_LEN + APP_RESP_LEN, key_cont, 0, key_cont.length);
                System.arraycopy(key_cont, 0, key_wrap_id, 0, key_wrap_id.length);
                System.arraycopy(key_cont, key_wrap_id.length, iv, 0, iv.length);
                System.arraycopy(key_cont, key_wrap_id.length + iv.length, kexp, 0, kexp.length);

                BigInteger keywrap_id = new BigInteger(key_wrap_id);
                if (!keywrap_id.equals(this.KeyCtrA)) {
                    System.out.println("[Protoqa.decryptSKKResp()] Error: key_wrap_id != KeyCtr");
                    return new byte[0];
                }

                byte[] kenc_b = new byte[32];
                byte[] kmac_b = new byte[32];
                Protoqa_form_kexp15_keys(this.KexpKey, kenc_b, kmac_b, this.SKKID, this.SeqNumSKK);
                SecretKey kenc = gostCrypto.importMagmaKey(kenc_b);
                SecretKey kmac = gostCrypto.importMagmaKey(kmac_b);
                byte[] q = gostCrypto.magmaKimp15(kenc, kmac, kexp, iv);

                //если пришел seed, тут сразу и переидем на новые ключи
                //не перехожу, возвращаю seed
                //иначе возвращаем ключ для абонентской связи

                return q;
            }
            else if(msg[1 + 16*2 + 4 + 1] == 3)
            {
                int RepCodesCnt = decr_msg[APP_HEADER_LEN];
                byte[] RepCodes = new byte[2];
                for (int i = 0; i < RepCodesCnt; i++)
                {
                    System.arraycopy(decr_msg, APP_HEADER_LEN + 1 + (i*2), RepCodes, 0, 2);
                    //BigInteger code = new BigInteger(RepCodes);
                    //тут надо вернуть какую-то ошибку, наверно
                }
                return new byte[2];
            }
            else {
                System.out.println("[Protoqa.decryptSKKResp()] Error: resp_header.MsgType == 0x04; wrong resp_header.HeaderFlags != 2 or 3");
            }

        }
        else {
            System.out.println("[Protoqa.decryptSKKResp()] Error: wrong resp_header.MsgType != 0x04");
        }

        return new byte[0];
    }
}
