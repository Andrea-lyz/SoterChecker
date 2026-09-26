package com.andrealyz.soterchecker;

import android.util.Base64;

import org.json.JSONObject;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** Soter export blob: [u32 LE jsonLen][JSON][RSA-PSS signature]. */
public final class Blobs {

    public final int jsonLen;
    public final String json;
    public final JSONObject obj;
    public final byte[] signature;
    public final byte[] body;
    public final int total;
    /** The complete wire blob, for verbatim dumps and offline re-verification. */
    public final byte[] blob;

    private Blobs(int jsonLen, String json, JSONObject obj, byte[] signature, byte[] body,
                  int total, byte[] blob) {
        this.jsonLen = jsonLen;
        this.json = json;
        this.obj = obj;
        this.signature = signature;
        this.body = body;
        this.total = total;
        this.blob = blob;
    }

    public static Blobs parse(byte[] data) throws Exception {
        if (data == null) {
            throw new Exception("null export data");
        }
        if (data.length < 8) {
            throw new Exception("short blob len=" + data.length);
        }
        int n = (data[0] & 0xff) | ((data[1] & 0xff) << 8) | ((data[2] & 0xff) << 16) | ((data[3] & 0xff) << 24);
        if (n <= 0 || 4 + n > data.length) {
            throw new Exception("jsonLen=" + n + " does not fit total=" + data.length);
        }
        byte[] body = Arrays.copyOfRange(data, 4, 4 + n);
        String json = new String(body, "UTF-8");
        JSONObject obj = new JSONObject(json);
        byte[] sig = Arrays.copyOfRange(data, 4 + n, data.length);
        return new Blobs(n, json, obj, sig, body, data.length, data);
    }

    public static PublicKey pemToRsaKey(String pem) throws Exception {
        String inner = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.decode(inner, Base64.DEFAULT);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * Returns the scheme that verifies, or null when none does.
     *
     * The captured chain is RSA-PSS with SHA-256, MGF1-SHA-256 and salt 20, but
     * Conscrypt's "SHA256withRSA/PSS" is not guaranteed to honour an explicit
     * MGF1 choice, so the detector probes the plausible combinations and reports
     * which one matched instead of trusting one spelling.
     */
    public static String probePss(PublicKey key, byte[] body, byte[] sig) {
        if (key == null || body == null || sig == null) {
            return null;
        }
        String[] algs = {"RSASSA-PSS", "SHA256withRSA/PSS"};
        String[] mgfs = {"SHA-256", "SHA-1"};
        int[] salts = {20, 32};
        for (String mgf : mgfs) {
            for (int salt : salts) {
                for (String alg : algs) {
                    try {
                        Signature s = Signature.getInstance(alg);
                        MGF1ParameterSpec spec = "SHA-256".equals(mgf)
                                ? MGF1ParameterSpec.SHA256 : MGF1ParameterSpec.SHA1;
                        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", spec, salt, 1));
                        s.initVerify(key);
                        s.update(body);
                        if (s.verify(sig)) {
                            return alg + ", MGF1-" + mgf + ", salt=" + salt;
                        }
                    } catch (Throwable ignored) {
                        // unsupported spelling on this platform: try the next
                    }
                }
            }
        }
        return null;
    }

    /**
     * EMSA-PSS-VERIFY (RFC 8017 9.1.2) computed on the RSA public key itself.
     *
     * The real chain is EMSA-PSS with SHA-256, MGF1-SHA-256 and a 20-byte salt.
     * Conscrypt's PSS spellings neither accept the explicit MGF1 choice reliably
     * nor verify this scheme, so the detector masks and hashes the block itself
     * and reports the platform probe separately.
     */
    public static boolean verifyPssRaw(PublicKey key, byte[] body, byte[] sig, int saltLen) {
        try {
            RSAPublicKey rsa = (RSAPublicKey) key;
            int emBits = rsa.getModulus().bitLength() - 1;
            int emLen = (emBits + 7) / 8;
            int hLen = 32;
            if (sig.length != (rsa.getModulus().bitLength() + 7) / 8 || emLen < hLen + saltLen + 2) {
                return false;
            }
            BigInteger m = new BigInteger(1, sig).modPow(rsa.getPublicExponent(), rsa.getModulus());
            byte[] em = toFixed(m, emLen);
            if (em[emLen - 1] != (byte) 0xbc) {
                return false;
            }
            int dbLen = emLen - hLen - 1;
            byte[] maskedDb = new byte[dbLen];
            System.arraycopy(em, 0, maskedDb, 0, dbLen);
            byte[] h = new byte[hLen];
            System.arraycopy(em, dbLen, h, 0, hLen);
            if ((maskedDb[0] & 0x80) != 0) {
                return false;
            }
            byte[] dbMask = mgf1(h, dbLen);
            byte[] db = new byte[dbLen];
            for (int i = 0; i < dbLen; i++) {
                db[i] = (byte) (maskedDb[i] ^ dbMask[i]);
            }
            db[0] &= 0x7f;
            int oneAt = emLen - hLen - saltLen - 2;
            for (int i = 0; i < oneAt; i++) {
                if (db[i] != 0) {
                    return false;
                }
            }
            if (db[oneAt] != 0x01) {
                return false;
            }
            byte[] salt = new byte[saltLen];
            System.arraycopy(db, oneAt + 1, salt, 0, saltLen);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] mHash = md.digest(body);
            md.reset();
            md.update(new byte[8]);
            md.update(mHash);
            md.update(salt);
            return MessageDigest.isEqual(h, md.digest());
        } catch (Throwable t) {
            return false;
        }
    }

    private static byte[] mgf1(byte[] seed, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] out = new byte[len];
        int off = 0;
        for (int counter = 0; off < len; counter++) {
            md.reset();
            md.update(seed);
            md.update(new byte[]{
                    (byte) (counter >>> 24), (byte) (counter >>> 16),
                    (byte) (counter >>> 8), (byte) counter});
            byte[] block = md.digest();
            int n = Math.min(block.length, len - off);
            System.arraycopy(block, 0, out, off, n);
            off += n;
        }
        return out;
    }

    private static byte[] toFixed(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        int n = Math.min(raw.length, len);
        System.arraycopy(raw, raw.length - n, out, len - n, n);
        return out;
    }
}
