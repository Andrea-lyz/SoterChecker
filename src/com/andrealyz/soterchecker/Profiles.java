package com.andrealyz.soterchecker;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;

/**
 * Vendor profile table: family, APK path, size, APK SHA-256, signer SHA-256.
 *
 * The built-in rows keep the probe working standalone. Dropping a profiles.json
 * next to the report overrides them, so a new vendor or ROM version is a data
 * change instead of a rebuild. The report records which source was used.
 */
final class Profiles {

    static final String[][] BUILTIN = {
            {"coloros/oplus", "/system_ext/app/SoterService/SoterService.apk", "74826",
                    "50acb3dc8b419bf312baf3d826d2295c34e333c11ad84e7c99f2ce24d6a7bf6d",
                    "fc98dae63ad39626c8c67fbe83f2f06f74932a9cd146b92cecfc6a047a904386"},
            {"hyperos/miui", "/vendor/app/SoterService/SoterService.apk", "33182",
                    "178ccdfa02e4a42eabbb4f37d766df83695116224e771aa8a499e239f0ffbe69",
                    "d45f076fe23a1a5b7f486e3ff41547a2023dbfe1fe73353b1e48ebdfed72cc6f"},
            /* HyperOS 4 / Android 17 moved the package to /product. Sampled 2026-09-26
             * from a live device (2509FPN0BC): size, APK hash and signer all come from
             * that device, the APK hash cross-checked against the run's own truncated
             * reading (470a2bd7abba3222...). */
            {"hyperos/miui", "/product/app/SoterService/SoterService.apk", "45582",
                    "470a2bd7abba3222c0cf3a1a54fc5efcfd897dc8c89d1e7d05d54aa81f0d9b78",
                    "c9009d01ebf9f5d0302bc71b2fe9aa9a47a432bba17308a3111b75d7b2149025"},
    };

    static String source = "builtin";

    private Profiles() {
    }

    static String[][] load(Context ctx) {
        File f = ctx.getExternalFilesDir(null) == null ? null
                : new File(ctx.getExternalFilesDir(null), "profiles.json");
        if (f == null || !f.isFile()) {
            source = "builtin";
            return BUILTIN;
        }
        try {
            byte[] raw = new byte[(int) f.length()];
            FileInputStream in = new FileInputStream(f);
            int n = in.read(raw);
            in.close();
            JSONArray arr = new JSONObject(new String(raw, 0, n, "UTF-8")).getJSONArray("profiles");
            String[][] rows = new String[arr.length()][5];
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                rows[i] = new String[]{
                        o.optString("family"), o.optString("path"), o.optString("size"),
                        o.optString("apk_sha256"), o.optString("signer_sha256")};
            }
            if (rows.length == 0) {
                source = "external-empty:builtin";
                return BUILTIN;
            }
            source = "external(rows=" + rows.length + ")";
            return rows;
        } catch (Throwable t) {
            source = "external-unusable(" + t.getClass().getSimpleName() + "):builtin";
            return BUILTIN;
        }
    }
}
