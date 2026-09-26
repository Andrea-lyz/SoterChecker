package com.andrealyz.soterchecker;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;
import android.util.Base64;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;

import com.tencent.soter.core.SoterCore;
import com.tencent.soter.core.model.SoterCoreData;
import com.tencent.soter.soterserver.ISoterService;
import com.tencent.soter.soterserver.SoterDeviceResult;
import com.tencent.soter.soterserver.SoterExportResult;
import com.tencent.soter.soterserver.SoterExtraParam;
import com.tencent.soter.soterserver.SoterSessionResult;
import com.tencent.soter.soterserver.SoterSignResult;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Local Soter semantics detector, application vantage.
 *
 * Measures what this uid sees: package visibility, APK path readability, component
 * resolution and binding, the whole ISoterService transaction matrix, and the local
 * cryptographic self-consistency of every exported blob. Reads only; the only writes
 * are the probe's own ASK/AuthKey under its own uid and the report file.
 */
public class SoterCheckerActivity extends Activity {

    private static final String TAG = "SoterChecker";
    private static final String PKG = "com.tencent.soter.soterserver";
    private static final String ACTION = "com.tencent.soter.soterserver.ISoterService";
    private static final String STOCK_PATH = "/system_ext/app/SoterService/SoterService.apk";
    private static final String STOCK_DIR = "/system_ext/app/SoterService";
    /**
     * One row per vendor we have sampled: family, APK path, size, APK SHA-256,
     * signer SHA-256. An empty hash means "not readable without root yet" - the
     * profile still identifies the layout, it just cannot verify the bytes.
     */
    /** Loaded from profiles.json when present, otherwise the built-in table. */
    static String[][] PROFILES = Profiles.BUILTIN;
    private static final String STOCK_SHA256 =
            "50acb3dc8b419bf312baf3d826d2295c34e333c11ad84e7c99f2ce24d6a7bf6d";
    private static final String[] ASK_KEYS = {"pub_key", "cpu_id", "counter", "uid"};
    /**
     * Result JSON of the stock backend on this ROM. The vendor TA builds it in
     * this order; the string table next to construct_soter_sign_data is
     * "raw fid counter tee_n QSEE tee_v fp_n fp_v cpu_id uid".
     *
     * rsa_pss_saltlen and fc_n/bo_t belong to other vendors' samples (Huawei),
     * so their absence is correct here and their presence is only informative.
     */
    private static final String[] SIGN_KEYS = {
            "raw", "fid", "counter", "tee_n", "tee_v", "fp_n", "fp_v", "cpu_id", "uid"
    };
    private static final String[] VENDOR_OPTIONAL_KEYS = {
            "rsa_pss_saltlen", "fc_n", "fc_v", "bo_t", "bf_t"
    };

    private final List<JSONObject> checks = new ArrayList<JSONObject>();
    private final StringBuilder screen = new StringBuilder();
    private TextView tv;
    private WebView webView;
    private volatile boolean pageReady;
    private volatile boolean revealed;
    /** Kept from persist() so the result page can be handed the full report. */
    private volatile String reportJson;

    private volatile ISoterService svc;
    private long bindMs = -1;
    private String attkPem;
    private boolean refmode;
    /** True while the page-triggered biometric signing round is running. */
    private volatile boolean fingerprintRun;
    /** Set by X13: true until this app proves it can enumerate installed packages. */
    private boolean listCapabilityLimited = true;
    private final JSONObject dump = new JSONObject();
    private final CountDownLatch latch = new CountDownLatch(1);

    private final ServiceConnection conn = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName n, IBinder b) {
            svc = ISoterService.Stub.asInterface(b);
            latch.countDown();
        }
        @Override public void onServiceDisconnected(ComponentName n) {
            svc = null;
        }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            String b64 = getIntent() == null ? null : getIntent().getStringExtra("attk_b64");
            if (b64 != null && !b64.isEmpty()) {
                attkPem = new String(Base64.decode(b64, Base64.DEFAULT), "UTF-8");
            }
            refmode = getIntent() != null && getIntent().getBooleanExtra("refmode", false);
        } catch (Throwable t) {
            Log.e(TAG, "attk extra unreadable", t);
        }
        PROFILES = Profiles.load(this);
        try {
            // The run is covered by the progress overlay in the page from the first
            // frame; the raw check log only stays in logcat.
            webView = new WebView(this);
            webView.getSettings().setJavaScriptEnabled(true);
            // The page offers to finish the signature chain with one biometric
            // signing round; the prompt has to run here, in this process.
            webView.addJavascriptInterface(new FingerprintBridge(), "SoterChecker");
            webView.setWebViewClient(new WebViewClient() {
                @Override public void onPageFinished(WebView view, String url) {
                    pageReady = true;
                    reveal(view);
                }
            });
            setContentView(webView);
            webView.loadUrl("file:///android_asset/result.html");
        } catch (Throwable t) {
            Log.e(TAG, "webview unavailable, falling back to the text log", t);
            webView = null;
            tv = new TextView(this);
            tv.setTextSize(9f);
            setContentView(tv);
        }
        new Thread(new Runnable() { @Override public void run() {
            try {
                probe();
            } catch (Throwable t) {
                check("X", "harness", "fail", "probe completes", String.valueOf(t), "");
                Log.e(TAG, "probe failed", t);
            } finally {
                persist();
            }
            if (refmode) {
                // Stock-reference runs stay non-visual so the witness flow is unchanged.
                finish();
            } else {
                runOnUiThread(new Runnable() { @Override public void run() { showResult(); } });
            }
        } }).start();
    }

    /** The harness owns the report write, so a partial run still produces evidence. */
    private void probe() throws Exception {
        final int uid = Process.myUid();
        check("E1", "env", "info",
                "record vantage",
                "pkg=" + getPackageName() + " uid=" + uid + " sdk=" + android.os.Build.VERSION.SDK_INT
                        + " model=" + android.os.Build.MODEL
                        + " brand=" + android.os.Build.BRAND
                        + " manufacturer=" + android.os.Build.MANUFACTURER
                        + " device=" + android.os.Build.DEVICE
                        + " hardware=" + android.os.Build.HARDWARE
                        + " fingerprint=" + android.os.Build.FINGERPRINT,
                "sec=" + sec());

        visibility(uid);
        tick("bind", "");
        boolean bound = bind();
        if (bound) {
            if (refmode) {
                // The SDK has to be live before FingerprintManagerCompat is loaded: its
                // static initializer picks the Api23 implementation only when
                // SoterCore.isNativeSupportSoter() is already true, otherwise every
                // hardware check answers false and the prompt never appears.
                sdkLevel();
                reference(uid);
            } else {
                transactions(uid);
                sdkLevel();
            }
        } else {
            check("T0", "transactions", "fail", "service bindable", "bind failed", "S4 failed");
        }
    }

    /**
     * Stock-device reference run. It never generates an ASK, because a registered
     * identity must survive; it creates exactly one throwaway AuthKey, asks for a
     * real fingerprint through the same compat call the official SDK uses on the
     * Treble path, and removes the key again at the end.
     */
    private void reference(int uid) throws Exception {
        boolean hasAsk = svc.hasAskAlready(uid);
        check("R1", "reference", hasAsk ? "pass" : "fail",
                "an ASK created earlier is still present, and this run never makes one",
                "hasAskAlready=" + hasAsk, "generating an ASK here would invalidate the registration");

        SoterExportResult ask = svc.getAppSecureKey(uid);
        check("R2", "reference", ask != null && ask.resultCode == 0 ? "pass" : "fail",
                "getAppSecureKey rc=0", describe(ask), "");
        Blobs askBlob = null;
        if (ask != null && ask.resultCode == 0 && ask.exportData != null) {
            askBlob = Blobs.parse(ask.exportData);
            try {
                dump.put("askB64", Base64.encodeToString(askBlob.blob, Base64.NO_WRAP));
            } catch (Throwable ignored) {
            }
            check("R3", "reference", "info", "record the ASK identity",
                    "counter=" + askBlob.obj.optString("counter")
                            + " uid=" + askBlob.obj.optString("uid")
                            + " cpu_id=" + mask(askBlob.obj.optString("cpu_id")), "");
            if (attkPem != null) {
                PublicKey attk = Blobs.pemToRsaKey(attkPem);
                boolean ok = Blobs.verifyPssRaw(attk, askBlob.body, askBlob.signature, 20);
                check("R4", "reference", ok ? "pass" : "fail",
                        "the stock ASK verifies with the stock ATTK public key",
                        "EMSA-PSS/SHA-256/salt=20 -> " + ok,
                        "platform probe=" + Blobs.probePss(attk, askBlob.body, askBlob.signature));
            }
        }

        SoterDeviceResult dev = svc.getDeviceId();
        String devHex = dev != null && dev.exportData != null ? hex(dev.exportData) : "-";
        check("R5", "reference", dev != null && dev.resultCode == 0 && dev.exportData != null
                && dev.exportData.length == 16 ? "pass" : "fail",
                "getDeviceId returns 16 raw bytes",
                dev == null ? "null" : "rc=" + dev.resultCode + " len=" + dev.exportDataLength
                        + " hex=" + mask(devHex), "");
        check("R6", "reference", "info", "fingerprint_type", "result=" + extraParam("fingerprint_type"), "");
        check("R7", "reference", "info", "unknown kname on getAuthKey",
                describe(svc.getAuthKey(uid, "sotercheck-missing-" + System.currentTimeMillis())),
                "the vendor answer is -6 with length 0, not the -5 a dead TA reports");
        String missing = "sotercheck-gone-" + System.currentTimeMillis();
        SoterSessionResult missSess = svc.initSigh(uid, missing, "sotercheck-x");
        check("R7b", "reference", "info", "unknown kname on initSign",
                missSess == null ? "null" : ("rc=" + missSess.resultCode),
                "compare with the software TA, which answers -5 here");
        check("R7c", "reference", "info", "unknown kname on removeAuthKey",
                "rc=" + svc.removeAuthKey(uid, missing), "");
        check("R7d", "reference", "info", "unknown kname on hasAuthKey",
                "hasAuthKey=" + svc.hasAuthKey(uid, missing), "");
        check("R8", "reference", "info", "unknown session", signDescribe(svc.finishSign(424242L)),
                "the vendor answer is -1000");

        String kname = "sotercheck_ref_" + System.currentTimeMillis();
        int gen = svc.generateAuthKey(uid, kname);
        SoterExportResult auth = svc.getAuthKey(uid, kname);
        check("R9", "reference", gen == 0 && auth != null && auth.resultCode == 0 ? "pass" : "fail",
                "generateAuthKey rc=0 for one throwaway key",
                "gen=" + gen + " export=" + describe(auth), "name=" + kname);
        Blobs authBlob = null;
        if (auth != null && auth.resultCode == 0 && auth.exportData != null) {
            authBlob = Blobs.parse(auth.exportData);
            try {
                dump.put("authB64", Base64.encodeToString(authBlob.blob, Base64.NO_WRAP));
            } catch (Throwable ignored) {
            }
            if (askBlob != null) {
                boolean ok = Blobs.verifyPssRaw(
                        Blobs.pemToRsaKey(askBlob.obj.getString("pub_key")),
                        authBlob.body, authBlob.signature, 20);
                check("R10", "reference", ok ? "pass" : "fail",
                        "the stock AuthKey verifies with the stock ASK public key",
                        "EMSA-PSS/SHA-256/salt=20 -> " + ok, "");
            }
        }

        String challenge = "sotercheck-ref-chal-" + System.currentTimeMillis();
        SoterSessionResult sess = svc.initSigh(uid, kname, challenge);
        check("R11", "reference", sess != null && sess.resultCode == 0 ? "pass" : "fail",
                "initSign rc=0", sess == null ? "null" : "rc=" + sess.resultCode, "");
        if (sess != null && sess.resultCode == 0) {
            Log.i(TAG, "fingerprint prompt is up; waiting up to 120s for a press");
            check("R12", "reference", "info", "ask the user for a fingerprint",
                    "prompt=" + fingerprintPrompt(),
                    "the vendor TA signs only inside a fresh biometric match");
            long t0 = System.currentTimeMillis();
            SoterSignResult sr = svc.finishSign(sess.session);
            long dt = System.currentTimeMillis() - t0;
            check("R13", "reference", sr != null && sr.resultCode == 0 ? "pass" : "fail",
                    "finishSign rc=0 after a real fingerprint (-26 is the no-biometric answer)",
                    sr == null ? "null" : ("rc=" + sr.resultCode + " len=" + sr.exportDataLength
                            + " ms=" + dt), "");
            if (sr != null && sr.resultCode == 0 && sr.exportData != null) {
                Blobs sign = Blobs.parse(sr.exportData);
                try {
                    dump.put("signB64", Base64.encodeToString(sign.blob, Base64.NO_WRAP));
                } catch (Throwable ignored) {
                }
                check("R14", "reference", keysMatch(sign.obj, SIGN_KEYS) ? "pass" : "warn",
                        "the stock result keys are exactly " + Arrays.toString(SIGN_KEYS),
                        "keys=" + keysOf(sign.obj) + " " + keyDiff(sign.obj, SIGN_KEYS), "");
                check("R15", "reference", orderOk(sign.json, SIGN_KEYS) ? "pass" : "warn",
                        "the stock wire order matches the string table",
                        "firstKeys=" + leadingKeys(sign.json, 9), "");
                check("R16", "reference", challenge.equals(sign.obj.optString("raw")) ? "pass" : "fail",
                        "raw carries the challenge verbatim",
                        "raw=" + sign.obj.optString("raw"), "");
                check("R17", "reference", "info", "stock identity fields",
                        "tee_n=" + sign.obj.optString("tee_n") + " tee_v=" + sign.obj.optString("tee_v")
                                + " fp_n=" + sign.obj.optString("fp_n")
                                + " fp_v=" + sign.obj.optString("fp_v")
                                + " saltlen=" + sign.obj.optString("rsa_pss_saltlen", "(absent)"), "");
                if (authBlob != null) {
                    boolean ok = Blobs.verifyPssRaw(
                            Blobs.pemToRsaKey(authBlob.obj.getString("pub_key")),
                            sign.body, sign.signature, 20);
                    check("R18", "reference", ok ? "pass" : "fail",
                            "the stock result verifies with the stock AuthKey public key",
                            "EMSA-PSS/SHA-256/salt=20 -> " + ok, "");
                }
            }
        }

        int rm = svc.removeAuthKey(uid, kname);
        boolean after = svc.hasAuthKey(uid, kname);
        check("R19", "reference", rm == 0 && !after ? "pass" : "warn",
                "the throwaway AuthKey is removed again",
                "removeRc=" + rm + " hasAuthKey=" + after + " name=" + kname, "");
    }

    private String extraParam(String key) {
        try {
            SoterExtraParam p = svc.getExtraParam(key);
            return p == null ? "null" : String.valueOf(p.result);
        } catch (Throwable t) {
            return "EXC " + t.getClass().getSimpleName();
        }
    }

    private static String signDescribe(SoterSignResult r) {
        return r == null ? "null" : ("rc=" + r.resultCode + " len=" + r.exportDataLength);
    }

    /**
     * The official SDK's Treble branch authenticates with a null CryptoObject
     * (TaskAuthentication.performStartFingerprintLogic(null)), so the prompt is the
     * plain system fingerprint UI; only the session it opens matters to the TA.
     */
    private String fingerprintPrompt() {
        final CountDownLatch done = new CountDownLatch(1);
        final String[] outcome = new String[]{"timeout after 90s"};
        runOnUiThread(new Runnable() { @Override public void run() {
            try {
                com.tencent.soter.core.fingerprint.FingerprintManagerCompat mgr =
                        com.tencent.soter.core.fingerprint.FingerprintManagerCompat.from(
                                SoterCheckerActivity.this);
                if (!mgr.isHardwareDetected() || !mgr.hasEnrolledFingerprints()) {
                    outcome[0] = "no fingerprint hardware, or none enrolled";
                    done.countDown();
                    return;
                }
                mgr.authenticate(
                        new com.tencent.soter.core.fingerprint.FingerprintManagerCompat.CryptoObject(
                                (Signature) null),
                        0, null,
                        new com.tencent.soter.core.fingerprint.FingerprintManagerCompat
                                .AuthenticationCallback() {
                            @Override public void onAuthenticationSucceeded(
                                    com.tencent.soter.core.fingerprint.FingerprintManagerCompat
                                            .AuthenticationResult result) {
                                outcome[0] = "matched";
                                done.countDown();
                            }
                            @Override public void onAuthenticationError(int id, CharSequence msg) {
                                outcome[0] = "error " + id + ": " + msg;
                                done.countDown();
                            }
                            @Override public void onAuthenticationCancelled() {
                                outcome[0] = "cancelled";
                                done.countDown();
                            }
                            @Override public void onAuthenticationFailed() {
                                Log.i(TAG, "fingerprint not recognized; still waiting");
                            }
                        }, null);
            } catch (Throwable t) {
                outcome[0] = "EXC " + t;
                done.countDown();
            }
        } });
        try {
            done.await(120, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }
        return outcome[0];
    }

    // ---- S: visibility and bindability ------------------------------------------------

    private void visibility(int uid) {
        PackageManager pm = getPackageManager();
        String sourceDir = "?";
        try {
            PackageInfo pi = pm.getPackageInfo(PKG,
                    PackageManager.GET_SIGNING_CERTIFICATES | PackageManager.GET_META_DATA);
            sourceDir = pi.applicationInfo.sourceDir;
            boolean system = (pi.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            boolean pathOk = isProfilePath(sourceDir);
            check("S1", "visibility", pathOk && system ? "pass" : "warn",
                    "getPackageInfo ok, FLAG_SYSTEM, sourceDir matches a sampled vendor profile",
                    "sourceDir=" + sourceDir + " system=" + system
                            + " ver=" + pi.versionName + "/" + pi.getLongVersionCode()
                            + " svcUid=" + pi.applicationInfo.uid,
                    "expected svcUid=10279, versionName=1.0.1");

            String sigHash = "-";
            try {
                android.content.pm.Signature[] signers =
                        pi.signingInfo.getApkContentsSigners();
                if (signers != null && signers.length > 0) {
                    sigHash = sha256Hex(signers[0].toByteArray());
                }
            } catch (Throwable t) {
                sigHash = "ERR " + t.getClass().getSimpleName();
            }
            check("S6", "visibility", "info", "record signer", "signerSha256=" + sigHash,
                    "compare against a stored baseline; a replaced APK changes this");

            int state = pm.getApplicationEnabledSetting(PKG);
            String stateName = state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED ? "ENABLED"
                    : state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED ? "DISABLED"
                    : state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER ? "DISABLED_USER"
                    : state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED
                    ? "DISABLED_UNTIL_USED" : "DEFAULT";
            check("S5", "visibility", (state == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
                    || state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) ? "pass" : "fail",
                    "enabled setting DEFAULT or ENABLED",
                    stateName + "(" + state + ") enabled=" + pi.applicationInfo.enabled,
                    "freezing tools use pm disable-user / pm suspend");
        } catch (PackageManager.NameNotFoundException e) {
            check("S1", "visibility", "fail", "getPackageInfo ok",
                    "NameNotFoundException", "package hidden from this uid");
            check("S5", "visibility", "info", "enabled state",
                    "unavailable: the package is not visible to this uid",
                    "a PM-level hide removes this channel too");
            check("S6", "visibility", "info", "signer",
                    "unavailable: the package is not visible to this uid",
                    "covering PackageManager is what such a disguise has to do");
        } catch (Throwable t) {
            check("S1", "visibility", "warn", "getPackageInfo ok", String.valueOf(t), "");
        }

        boolean reportedInstalled = !"?".equals(sourceDir);
        File apk = new File(sourceDir);
        try {
            boolean exists = apk.exists();
            long len = apk.length();
            String hash = exists ? sha256File(apk) : "-";
            byte[] head = exists ? read(new FileInputStream(apk), 4) : new byte[0];
            String magic = exists && head.length == 4
                    ? String.format("%02x%02x%02x%02x", head[0], head[1], head[2], head[3]) : "-";
            boolean stock = isProfileHash(hash);
            // A package PM will not describe has no known path either: that is a blinded
            // channel, not evidence of masking, so it must not be reported as a failure.
            String status = !reportedInstalled ? "info"
                    : (!exists ? "fail" : (stock ? "pass" : "warn"));
            check("S2", "visibility", status,
                    "readable, len=74826, sha256=" + STOCK_SHA256.substring(0, 16) + "..., magic=504b0304",
                    "exists=" + exists + " len=" + len + " magic=" + magic
                            + " sha256=" + (hash.length() > 16 ? hash.substring(0, 16) + "..." : hash)
                            + (reportedInstalled ? "" : " (path unknown: PM returned no package)"),
                    stock ? "content identical to the stock copy" : "content differs from the stock hash");
            // No privileges needed: PM reports an installed system package whose own
            // sourceDir this uid cannot see. Stock devices cannot produce that pair.
            check("X2", "visibility", (!reportedInstalled || exists) ? "pass" : "fail",
                    "the APK path PM reports for an installed system package is readable",
                    "pmSourceDir=" + sourceDir + " exists=" + exists,
                    "PM says the package is installed while its APK is invisible to this uid");
        } catch (Throwable t) {
            check("S2", "visibility", "fail", "APK readable from this uid", String.valueOf(t),
                    "path masking shows up here");
        }

        // Independent of PackageManager on purpose: a hide that blinds PM (HMA and
        // friends) does not touch the filesystem, so the well-known stock path still
        // identifies the component. Path masking defeats this one; PM hiding defeats
        // the query above; covering both is what a complete disguise costs.
        final String stockPath = stockPathFor(sourceDir);
        final String stockDir = stockDirOf(stockPath);
        try {
            File stockApk = new File(stockPath);
            boolean stockExists = stockApk.exists();
            String stockHash = stockExists ? sha256File(stockApk) : "-";
            String profile = profileOf(stockPath, stockHash, stockApk.length());
            check("X3", "visibility", !stockExists ? "info"
                            : ("match".equals(profile) ? "pass" : "warn"),
                    "the stock path carries an APK matching a sampled vendor profile",
                    "path=" + stockPath + " exists=" + stockExists
                            + " size=" + stockApk.length()
                            + " sha256=" + (stockHash.length() > 16
                            ? stockHash.substring(0, 16) + "..." : stockHash)
                            + " profile=" + profile,
                    "checked without PackageManager, so blinding PM does not hide it");
        } catch (Throwable t) {
            check("X3", "visibility", "info", "stock path probe", String.valueOf(t), "");
        }

        // Which of the sampled vendor layouts this device carries. A profile whose
        // hashes were never readable without root still identifies the layout.
        try {
            StringBuilder rows = new StringBuilder();
            int matches = 0;
            for (String[] p : PROFILES) {
                File f = new File(p[1]);
                boolean exists = f.exists();
                String hash = exists ? sha256File(f) : "-";
                boolean hashKnown = p[3].length() > 0;
                boolean hashOk = hashKnown && p[3].equals(hash);
                boolean sizeOk = exists && String.valueOf(f.length()).equals(p[2]);
                if (exists && (hashOk || (!hashKnown && sizeOk))) {
                    matches++;
                }
                rows.append(p[0]).append(':').append(exists ? "found" : "absent")
                        .append(hashKnown ? (hashOk ? "/hash-match" : "/hash-differs")
                                : "/hash-unknown")
                        .append(sizeOk ? "/size-match" : "/size-differs").append(' ');
            }
            check("X11", "visibility", matches > 0 ? "pass" : "info",
                    "which sampled vendor profile this device carries",
                    "profiles=" + PROFILES.length + " matches=" + matches
                            + " [" + rows.toString().trim() + "]",
                    "the software TA answers the same on every vendor");
        } catch (Throwable t) {
            check("X11", "visibility", "info", "vendor profile scan", String.valueOf(t), "");
        }

        // The same filesystem question asked twice, one layer apart. A Java-level hook
        // can fake File.exists without touching libc, so a disagreement between the two
        // answers is itself the finding.
        try {
            int agree = 0;
            int disagree = 0;
            StringBuilder detail = new StringBuilder();
            for (String[] p : PROFILES) {
                boolean javaSays = new File(p[1]).exists();
                boolean accessSays = false;
                try {
                    accessSays = android.system.Os.access(p[1], android.system.OsConstants.F_OK);
                } catch (Throwable ignored) {
                    // treat as no
                }
                // A separate native process asks the same question: neither a Java hook
                // nor an injection aimed at this process name reaches it.
                boolean processSays = false;
                try {
                    processSays = exec("/system/bin/ls -d " + p[1]).trim().length() > 0;
                } catch (Throwable ignored) {
                    // treat as no
                }
                if (javaSays == accessSays && javaSays == processSays) {
                    agree++;
                } else {
                    disagree++;
                    detail.append(p[0]).append("[java=").append(javaSays)
                            .append(" access=").append(accessSays)
                            .append(" process=").append(processSays).append("] ");
                }
            }
            check("X12", "visibility", disagree == 0 ? "pass" : "fail",
                    "the Java, libc and separate-process answers agree about every stock path",
                    "paths=" + PROFILES.length + " agree=" + agree + " disagree=" + disagree
                            + " [" + detail.toString().trim() + "]",
                    "a forgery confined to this process shows up as a layer disagreement");
        } catch (Throwable t) {
            check("X12", "visibility", "info", "cross-layer probe", String.valueOf(t), "");
        }

        // A directory is a different inode from the file inside it, so a mask
        // configured for the APK alone leaves the parent listing intact - and the
        // name in that listing already says the component exists.
        try {
            File dir = new File(stockDir);
            boolean dirExists = dir.isDirectory();
            File parent = dir.getParentFile();
            String[] names = parent == null ? null : parent.list();
            boolean listed = false;
            if (names != null) {
                for (String n : names) {
                    if (dir.getName().equals(n)) {
                        listed = true;
                        break;
                    }
                }
            }
            check("X4", "visibility", (dirExists || listed) ? "pass" : "info",
                    "the stock directory answers even when the APK file does not",
                    "dir=" + stockDir + " isDirectory=" + dirExists
                            + " parentListingHasDir=" + listed,
                    "hiding one inode does not hide its neighbours");
        } catch (Throwable t) {
            check("X4", "visibility", "info", "directory probe", String.valueOf(t), "");
        }

        // Firmware claims about Soter live in world-readable properties; an ordinary
        // app can read them through getprop, no root involved.
        try {
            String props = exec("/system/bin/getprop");
            StringBuilder hits = new StringBuilder();
            int lineCount = 0;
            for (String line : props.split("\n")) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                lineCount++;
                String l = line.toLowerCase(java.util.Locale.US);
                if (l.contains("soter") || l.contains("boottime") && l.contains("soter")) {
                    hits.append(line.trim()).append("; ");
                }
            }
            check("X5", "visibility", "info", "record the firmware soter properties",
                    "propLines=" + lineCount + " hits="
                            + (hits.length() == 0 ? "(none)" : hits.toString().trim()),
                    "ro.boottime.* proves init started that HAL on this boot; init.svc shows it now");
        } catch (Throwable t) {
            check("X5", "visibility", "info", "property probe", String.valueOf(t), "");
        }

        // The hider's own configuration is a dimension too: on kernels whose sysfs
        // labels allow it, an app can read the mask list and see itself named.
        try {
            String params = readText("/sys/module/pathmask/parameters/target_paths");
            boolean namesSoter = params.contains("SoterService");
            check("X6", "visibility", namesSoter ? "pass" : "info",
                    "read the mask configuration as this uid",
                    "target_paths=" + params.trim(),
                    "the configuration names the hidden path when sysfs is readable");
        } catch (Throwable t) {
            check("X6", "visibility", "info", "read the mask configuration as this uid",
                    "unreadable: " + t.getClass().getSimpleName(),
                    "expected when sysfs is labelled system-only; the root vantage still reads it");
        }

        // Firmware family read from the ROM's own contents instead of the labels it
        // prints: a spoofed ro.product.brand still ships the OEM's system packages,
        // and an app enumerates those with the same call it uses for everything else.
        try {
            String[][] families = {
                    {"coloros/oplus", "com.oplus.", "com.coloros.", "com.oneplus."},
                    {"hyperos/miui", "com.miui.", "com.xiaomi.", "com.android.thememanager"},
                    {"originos/vivo", "com.vivo.", "com.iqoo."},
                    {"magicos/honor", "com.hihonor.", "com.honor."},
                    {"harmonyos/huawei", "com.huawei."},
            };
            List<PackageInfo> installed = pm.getInstalledPackages(0);
            String best = "(none)";
            int bestCount = 0;
            StringBuilder detail = new StringBuilder();
            for (String[] family : families) {
                int count = 0;
                for (PackageInfo p : installed) {
                    if (p.applicationInfo == null
                            || (p.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) {
                        continue;
                    }
                    for (int k = 1; k < family.length; k++) {
                        if (p.packageName.startsWith(family[k])) {
                            count++;
                            break;
                        }
                    }
                }
                if (count > 0) {
                    detail.append(family[0]).append('=').append(count).append(' ');
                }
                if (count > bestCount) {
                    bestCount = count;
                    best = family[0];
                }
            }
            check("X7", "visibility", bestCount >= 3 ? "pass" : "info",
                    "firmware family read from the ROM's own system packages",
                    "family=" + best + " systemPackages=" + bestCount
                            + " [" + detail.toString().trim() + "]",
                    "labels can be spoofed; dozens of OEM system packages cannot");
            try {
                dump.put("oemFamily", best);
                dump.put("oemFamilyCount", bestCount);
            } catch (Throwable ignored) {
            }
        } catch (Throwable t) {
            check("X7", "visibility", "info", "firmware family probe", String.valueOf(t), "");
        }

        // A PM-level hide has to hook every API that can answer about this package.
        // The sweep asks the same question through fourteen of them, one of which
        // parses the APK file instead of the package database. Every probe runs in
        // isolation, and a single leak is enough to see the component.
        try {
            final ComponentName service = new ComponentName(PKG,
                    "com.tencent.soter.soterserver.SoterService");
            final ComponentName receiver = new ComponentName(PKG,
                    "com.tencent.soter.soterserver.SoterService$UserAppUninstallReceiver");
            final String[] names = {
                    "queryIntentServices(actionOnly)",
                    "queryIntentServices(setPackage+disabled)",
                    "resolveService(setPackage+disabled)",
                    "getInstalledPackages(flags)",
                    "getInstalledApplications(disabled)",
                    "getApplicationInfo(flags)",
                    "getPackageInfo(flags)",
                    "getPackageUid",
                    "getPackageGids",
                    "isPackageSuspended",
                    "getInstallSourceInfo",
                    "getServiceInfo(component)",
                    "getReceiverInfo(component)",
                    "getPackageArchiveInfo(stockPath)",
            };
            StringBuilder detail = new StringBuilder();
            int leaks = sweep(detail, names, new LeakProbe[]{
                    () -> {
                        for (ResolveInfo ri : pm.queryIntentServices(new Intent(ACTION), 0)) {
                            if (ri.serviceInfo != null && PKG.equals(ri.serviceInfo.packageName)) {
                                return true;
                            }
                        }
                        return false;
                    },
                    () -> !pm.queryIntentServices(new Intent(ACTION).setPackage(PKG),
                            PackageManager.MATCH_DISABLED_COMPONENTS).isEmpty(),
                    () -> pm.resolveService(new Intent(ACTION).setPackage(PKG),
                            PackageManager.MATCH_DISABLED_COMPONENTS) != null,
                    () -> {
                        for (PackageInfo p : pm.getInstalledPackages(
                                PackageManager.MATCH_UNINSTALLED_PACKAGES
                                        | PackageManager.MATCH_DISABLED_COMPONENTS)) {
                            if (PKG.equals(p.packageName)) {
                                return true;
                            }
                        }
                        return false;
                    },
                    () -> {
                        for (ApplicationInfo a : pm.getInstalledApplications(
                                PackageManager.MATCH_DISABLED_COMPONENTS)) {
                            if (PKG.equals(a.packageName)) {
                                return true;
                            }
                        }
                        return false;
                    },
                    () -> pm.getApplicationInfo(PKG,
                            PackageManager.MATCH_DISABLED_COMPONENTS
                                    | PackageManager.MATCH_UNINSTALLED_PACKAGES) != null,
                    () -> pm.getPackageInfo(PKG,
                            PackageManager.MATCH_DISABLED_COMPONENTS
                                    | PackageManager.MATCH_UNINSTALLED_PACKAGES
                                    | PackageManager.GET_SIGNING_CERTIFICATES) != null,
                    () -> pm.getPackageUid(PKG, 0) > 0,
                    () -> pm.getPackageGids(PKG).length > 0,
                    () -> {
                        pm.isPackageSuspended(PKG);
                        return true;
                    },
                    () -> {
                        pm.getInstallSourceInfo(PKG);
                        return true;
                    },
                    () -> pm.getServiceInfo(service,
                            PackageManager.MATCH_DISABLED_COMPONENTS) != null,
                    () -> pm.getReceiverInfo(receiver,
                            PackageManager.MATCH_DISABLED_COMPONENTS) != null,
                    () -> {
                        PackageInfo archive = pm.getPackageArchiveInfo(stockPath,
                                PackageManager.GET_SIGNING_CERTIFICATES);
                        return archive != null && PKG.equals(archive.packageName);
                    },
            });
            check("X9", "visibility", leaks > 0 ? "pass" : "info",
                    "the same fact asked through every PackageManager path",
                    "probes=" + names.length + " leaking=" + leaks
                            + " [" + detail.toString().trim() + "]",
                    "one un-hooked API is enough to see the package");
        } catch (Throwable t) {
            check("X9", "visibility", "info", "cross-api sweep", String.valueOf(t), "");
        }

        // Masking one file is not masking the layout: the oat/vdex and lib side files
        // of an installed package live next to it and answer on their own.
        try {
            String apkName = stockPath.substring(stockPath.lastIndexOf('/') + 1);
            String base = apkName.endsWith(".apk")
                    ? apkName.substring(0, apkName.length() - 4) : apkName;
            String[] layout = {
                    stockPath,
                    stockDir,
                    stockDir + "/oat",
                    stockDir + "/oat/arm64",
                    stockDir + "/oat/arm64/" + base + ".vdex",
                    stockDir + "/lib",
                    stockDir + "/oat/arm",
                    stockDir + "/oat/arm/" + base + ".odex",
            };
            StringBuilder visible = new StringBuilder();
            int seen = 0;
            for (String p : layout) {
                if (new File(p).exists()) {
                    seen++;
                    visible.append(p.substring(p.lastIndexOf('/') + 1)).append(' ');
                }
            }
            check("X10", "visibility", seen == 0 ? "info" : "pass",
                    "the stock layout answers as a whole",
                    "paths=" + layout.length + " visible=" + seen
                            + " [" + visible.toString().trim() + "]",
                    "masking the APK alone leaves its side files in place");
        } catch (Throwable t) {
            check("X10", "visibility", "info", "stock layout probe", String.valueOf(t), "");
        }

        Intent i = new Intent(ACTION).setPackage(PKG);
        try {
            ResolveInfo ri = pm.resolveService(i, 0);
            List<ResolveInfo> all = pm.queryIntentServices(i, 0);
            // A frozen component disappears from the plain query, but PM still knows it
            // when the caller asks for disabled ones: that gap is the freeze signature.
            List<ResolveInfo> disabled = pm.queryIntentServices(i,
                    PackageManager.MATCH_DISABLED_COMPONENTS);
            check("X1", "visibility", "info", "record how the component answers queries",
                    "plainQuery=" + all.size() + " withDisabled=" + disabled.size(),
                    "a service visible only with MATCH_DISABLED_COMPONENTS exists but is disabled");
            String comp = ri == null || ri.serviceInfo == null ? "null"
                    : ri.serviceInfo.name;
            String proc = ri == null || ri.serviceInfo == null ? "-" : ri.serviceInfo.processName;
            int svcUid = ri == null || ri.serviceInfo == null || ri.serviceInfo.applicationInfo == null
                    ? -1 : ri.serviceInfo.applicationInfo.uid;
            boolean exported = ri != null && ri.serviceInfo != null && ri.serviceInfo.exported;
            check("S3", "visibility", ri != null && exported ? "pass" : "fail",
                    "resolveService returns SoterService, exported",
                    "component=" + comp + " exported=" + exported + " queryCount=" + all.size()
                            + " svcUid=" + svcUid + " process=" + proc,
                    "expected uid=10279 process=" + PKG);
        } catch (Throwable t) {
            check("S3", "visibility", "fail", "resolveService ok", String.valueOf(t), "");
        }

        try {
            List<PackageInfo> pkgs = pm.getInstalledPackages(0);
            // Capability first: an OEM appop (ColorOS/HyperOS expose GET_INSTALLED_APPS)
            // or a missing QUERY_ALL_PACKAGES turns every list into a one-package list.
            try {
                int perm = pm.checkPermission("android.permission.QUERY_ALL_PACKAGES",
                        getPackageName());
                int count = pkgs.size();
                int apps = pm.getInstalledApplications(0).size();
                String op = "unreadable";
                try {
                    android.app.AppOpsManager aom =
                            (android.app.AppOpsManager) getSystemService(Context.APP_OPS_SERVICE);
                    if (aom != null) {
                        int mode = aom.checkOpNoThrow("GET_INSTALLED_APPS", Process.myUid(),
                                getPackageName());
                        op = mode == android.app.AppOpsManager.MODE_ALLOWED ? "allowed"
                                : (mode == android.app.AppOpsManager.MODE_IGNORED ? "ignored"
                                : "mode=" + mode);
                    }
                } catch (Throwable t) {
                    // The platform's op table does not know this OEM op name; the list
                    // size below is the effect-based answer anyway.
                    op = "unnamed(" + t.getClass().getSimpleName() + ")";
                }
                // Effect-based: every real ROM installs hundreds of packages, so a list
                // this short means this app is being filtered, whatever the mechanism.
                boolean looksFiltered = count < 20 && apps < 20;
                listCapabilityLimited = perm != PackageManager.PERMISSION_GRANTED
                        || "ignored".equals(op) || looksFiltered;
                check("X13", "visibility", listCapabilityLimited ? "info" : "pass",
                        "this app can enumerate installed packages",
                        "permission="
                                + (perm == PackageManager.PERMISSION_GRANTED ? "granted" : "denied")
                                + " appop(GET_INSTALLED_APPS)=" + op
                                + " packages=" + count + " applications=" + apps
                                + " looksFiltered=" + looksFiltered,
                        "a filtered list blinds the list-based checks instead of contradicting them");
            } catch (Throwable t) {
                check("X13", "visibility", "info", "app list capability", String.valueOf(t), "");
            }
            boolean has = false;
            for (PackageInfo p : pkgs) {
                if (PKG.equals(p.packageName)) {
                    has = true;
                    break;
                }
            }
            // Presence always proves visibility. Absence is evidence of hiding only when
            // this app could have enumerated packages at all (see X13): a filtered list
            // hides every package exactly the way a hider would.
            check("S8", "visibility", has ? "pass" : (listCapabilityLimited ? "info" : "fail"),
                    "package list contains " + PKG + " (absence counts only with a full list)",
                    "count=" + pkgs.size() + " contains=" + has
                            + " listCapabilityLimited=" + listCapabilityLimited,
                    "with a filtered list the check is blind, not contradicted");
        } catch (Throwable t) {
            check("S8", "visibility", "warn", "package list readable", String.valueOf(t), "");
        }

    }

    private boolean bind() {
        try {
            long t0 = System.currentTimeMillis();
            boolean bound = bindService(new Intent(ACTION).setPackage(PKG), conn,
                    Context.BIND_AUTO_CREATE);
            boolean connected = false;
            if (bound) {
                connected = latch.await(8, TimeUnit.SECONDS) && svc != null;
            }
            bindMs = System.currentTimeMillis() - t0;
            check("S4", "visibility", bound && connected ? "pass" : "fail",
                    "bindService true, onServiceConnected within 8s",
                    "bound=" + bound + " connected=" + connected + " ms=" + bindMs,
                    "a frozen or disabled package cannot be bound");
            return bound && connected;
        } catch (Throwable t) {
            check("S4", "visibility", "fail", "bindService ok", String.valueOf(t), "");
            return false;
        }
    }

    // ---- T: transaction semantics ------------------------------------------------------

    private void transactions(int uid) throws Exception {
        int version = svc.getVersion();
        check("T1", "transactions", version > 0 ? "pass" : "fail", "getVersion > 0",
                "version=" + version, "stock and both software TAs answer 1");

        boolean hasAsk = svc.hasAskAlready(uid);
        int gen = svc.generateAppSecureKey(uid);
        SoterExportResult ask = svc.getAppSecureKey(uid);
        check("T2", "transactions", ask != null && ask.resultCode == 0 ? "pass" : "fail",
                "hasAskAlready then generateAppSecureKey then getAppSecureKey rc=0",
                "hasAsk=" + hasAsk + " generateRc=" + gen + " export=" + describe(ask),
                "this is the order every client uses");
        check("T3", "transactions",
                ask != null && ask.exportDataLength == (ask.exportData == null ? -1 : ask.exportData.length)
                        ? "pass" : "fail",
                "exportDataLength equals exportData.length",
                ask == null ? "null" : "len=" + ask.exportDataLength
                        + " data=" + (ask.exportData == null ? -1 : ask.exportData.length),
                "a software TA that writes 0 here is a known past defect");

        Blobs askBlob = null;
        if (ask != null && ask.exportData != null && ask.resultCode == 0) {
            try {
                askBlob = Blobs.parse(ask.exportData);
                check("C1", "crypto", askBlob.signature.length == 256 ? "pass" : "fail",
                        "[u32 jsonLen][JSON][256B signature]",
                        "jsonLen=" + askBlob.jsonLen + " jsonBytes=" + askBlob.body.length
                                + " sigBytes=" + askBlob.signature.length + " total=" + askBlob.total,
                        "");
                check("C6a", "crypto", keysMatch(askBlob.obj, ASK_KEYS) ? "pass" : "warn",
                        "export keys exactly " + Arrays.toString(ASK_KEYS),
                        "keys=" + keysOf(askBlob.obj), "a certs array means another backend");
            } catch (Throwable t) {
                check("C1", "crypto", "fail", "ASK blob parses", String.valueOf(t), "");
            }
        }

        if (askBlob != null) {
            try {
                dump.put("askB64", Base64.encodeToString(askBlob.blob, Base64.NO_WRAP));
            } catch (Throwable t) {
                Log.e(TAG, "ask dump failed", t);
            }
            try {
                String selfScheme = Blobs.probePss(Blobs.pemToRsaKey(askBlob.obj.getString("pub_key")),
                        askBlob.body, askBlob.signature);
                boolean selfRaw = Blobs.verifyPssRaw(
                        Blobs.pemToRsaKey(askBlob.obj.getString("pub_key")),
                        askBlob.body, askBlob.signature, 20);
                check("C2b", "crypto", "info", "an ASK blob is signed by the device key, not by itself",
                        "selfVerify=" + (selfRaw || selfScheme != null ? "yes" : "no"),
                        "captured chain is ASK <- ATTK, AuthKey <- ASK, result <- AuthKey");
            } catch (Throwable t) {
                check("C2b", "crypto", "info", "ASK self-verify probe", String.valueOf(t), "");
            }
            if (attkPem == null) {
                check("C2", "crypto", "info", "ASK signature verifies with the ATTK public key",
                        "skipped: no ATTK key supplied",
                        "the root vantage exports it with vendor.qti.hardware.soter tx 2");
            } else {
                try {
                    PublicKey attk = Blobs.pemToRsaKey(attkPem);
                    boolean ok = Blobs.verifyPssRaw(attk, askBlob.body, askBlob.signature, 20);
                    check("C2", "crypto", ok ? "pass" : "fail",
                            "ASK signature verifies with the ATTK public key",
                            "EMSA-PSS/SHA-256/MGF1-SHA-256/salt=20 -> " + ok,
                            "platform probe=" + Blobs.probePss(attk, askBlob.body, askBlob.signature));
                } catch (Throwable t) {
                    check("C2", "crypto", "fail", "ASK against the ATTK key", String.valueOf(t), "");
                }
            }
            check("C5a", "crypto", "info", "record identity fields",
                    "counter=" + askBlob.obj.optString("counter") + " uid=" + askBlob.obj.optString("uid")
                            + " cpu_id=" + mask(askBlob.obj.optString("cpu_id")),
                    "cpu_id must equal the getDeviceId bytes");
        }

        // T-uid: the Java layer replaces the passed uid with Binder.getCallingUid().
        int[] foreign = {0, 1000, 99999};
        StringBuilder uidEvidence = new StringBuilder();
        boolean uidOk = true;
        for (int fu : foreign) {
            SoterExportResult r = svc.getAppSecureKey(fu);
            String got = "-";
            if (r != null && r.resultCode == 0 && r.exportData != null) {
                try {
                    got = Blobs.parse(r.exportData).obj.optString("uid");
                    if (!String.valueOf(uid).equals(got)) {
                        uidOk = false;
                    }
                } catch (Throwable t) {
                    got = "parse-error";
                }
            } else if (r != null) {
                got = "rc=" + r.resultCode;
            }
            uidEvidence.append("pass ").append(fu).append(" -> uid=").append(got).append("; ");
        }
        check("T4", "transactions", uidOk ? "pass" : "fail",
                "a foreign uid argument never changes the returned identity",
                uidEvidence.toString().trim(), "expected uid=" + uid + " for every call");

        // negative semantics
        String missing = "sotercheck-missing-" + System.currentTimeMillis();
        SoterExportResult miss = svc.getAuthKey(uid, missing);
        int missCode = miss == null ? 0 : miss.resultCode;
        check("T5", "transactions",
                missCode == -6 && miss != null && miss.exportDataLength == 0 ? "pass"
                        : (missCode == -5 ? "warn" : "fail"),
                "getAuthKey(unknown kname) = -6 with length 0",
                miss == null ? "null" : describe(miss),
                "the live vendor TA answers -6 (PHB110 capture); -5 is the dead-TA spelling");
        SoterSignResult bogus = svc.finishSign(424242L);
        check("T6", "transactions", bogus != null && bogus.resultCode == -1000 ? "pass" : "fail",
                "finishSign(unknown session) = -1000",
                bogus == null ? "null" : "rc=" + bogus.resultCode + " len=" + bogus.exportDataLength,
                "the vendor TA uses -1000 here, not -22");
        SoterExtraParam fp = svc.getExtraParam("fingerprint_type");
        String fpValue = fp == null ? "null" : String.valueOf(fp.result);
        check("T7", "transactions", "2".equals(fpValue) ? "pass" : "warn",
                "getExtraParam(fingerprint_type) = 2",
                "result=" + fpValue, "");
        SoterExtraParam none = svc.getExtraParam("sotercheck_unknown_param");
        check("T8", "transactions", "info", "record unknown extra param",
                "result=" + (none == null ? "null" : String.valueOf(none.result)), "");

        SoterDeviceResult dev = svc.getDeviceId();
        String devHex = dev != null && dev.exportData != null ? hex(dev.exportData) : "-";
        check("T9", "transactions", dev != null && dev.resultCode == 0
                && dev.exportData != null && dev.exportData.length == 16 ? "pass" : "fail",
                "getDeviceId returns 16 raw bytes",
                dev == null ? "null" : "rc=" + dev.resultCode + " len=" + dev.exportDataLength
                        + " hex=" + mask(devHex), "");
        if (askBlob != null && !"-".equals(devHex)) {
            check("C5b", "crypto", devHex.equals(askBlob.obj.optString("cpu_id")) ? "pass" : "fail",
                    "cpu_id equals the getDeviceId hex",
                    "deviceIdHex=" + mask(devHex) + " cpuId=" + mask(askBlob.obj.optString("cpu_id")),
                    "");
        }

        // AuthKey + signing session
        String kname = "sotercheck_key_" + System.currentTimeMillis();
        int authRc = svc.generateAuthKey(uid, kname);
        boolean hasAuth = svc.hasAuthKey(uid, kname);
        SoterExportResult auth = svc.getAuthKey(uid, kname);
        check("T10", "transactions", authRc == 0 && hasAuth && auth != null && auth.resultCode == 0
                ? "pass" : "fail",
                "generateAuthKey rc=0, hasAuthKey true, getAuthKey rc=0",
                "genRc=" + authRc + " hasAuth=" + hasAuth + " export=" + describe(auth), "");

        Blobs authBlob = null;
        if (auth != null && auth.exportData != null && auth.resultCode == 0) {
            authBlob = Blobs.parse(auth.exportData);
            try {
                dump.put("authB64", Base64.encodeToString(authBlob.blob, Base64.NO_WRAP));
            } catch (Throwable ignored) {
            }
            check("C6b", "crypto", keysMatch(authBlob.obj, ASK_KEYS) ? "pass" : "warn",
                    "AuthKey export keys exactly " + Arrays.toString(ASK_KEYS),
                    "keys=" + keysOf(authBlob.obj), "");
            if (askBlob != null) {
                try {
                    boolean ok = Blobs.verifyPssRaw(
                            Blobs.pemToRsaKey(askBlob.obj.getString("pub_key")),
                            authBlob.body, authBlob.signature, 20);
                    check("C3", "crypto", ok ? "pass" : "fail",
                            "AuthKey signature verifies with the ASK public key",
                            "EMSA-PSS/SHA-256/salt=20 -> " + ok,
                            "the server-side sample verifies exactly this");
                } catch (Throwable t) {
                    check("C3", "crypto", "fail", "AuthKey verify", String.valueOf(t), "");
                }
            }
        }

        String challenge = "sotercheck-chal-" + System.currentTimeMillis();
        SoterSessionResult sess = svc.initSigh(uid, kname, challenge);
        check("T11", "transactions", sess != null && sess.resultCode == 0 ? "pass" : "fail",
                "initSign rc=0",
                sess == null ? "null" : "session=" + (sess.session != 0) + " rc=" + sess.resultCode,
                "session value recorded, not printed");

        long t0 = System.currentTimeMillis();
        SoterSignResult sr = sess != null && sess.resultCode == 0 ? svc.finishSign(sess.session) : null;
        long dt = System.currentTimeMillis() - t0;
        if (sr != null) {
            // Both branches are living answers: a software TA signs locally (rc=0);
            // a stock TA declines without a matched biometric (-26). Only the dead-TA
            // spelling (-5/-20) or another unexpected code is a deviation.
            boolean living = sr.resultCode == 0 || sr.resultCode == -26;
            check("T12", "transactions", living ? "pass" : "fail",
                    "finishSign gives a living answer without a local fingerprint",
                    "rc=" + sr.resultCode + " len=" + sr.exportDataLength + " ms=" + dt,
                    "0 = software TA signs locally; -26 = stock TA requires a matched fingerprint");
        }
        if (sr != null && sr.resultCode == 0 && sr.exportData != null) {
            Blobs sign = Blobs.parse(sr.exportData);
            try {
                dump.put("signB64", Base64.encodeToString(sign.blob, Base64.NO_WRAP));
            } catch (Throwable ignored) {
            }
            boolean keysOk = keysMatch(sign.obj, SIGN_KEYS);
            boolean onlyVendorExtras = keysOk || extraKeysAreVendorOptional(sign.obj);
            check("C6c", "crypto", keysOk ? "pass" : (onlyVendorExtras ? "info" : "warn"),
                    "result keys exactly " + Arrays.toString(SIGN_KEYS),
                    "keys=" + keysOf(sign.obj) + " " + keyDiff(sign.obj, SIGN_KEYS),
                    "stock builds raw/fid/counter/tee_n/tee_v/fp_n/fp_v/cpu_id/uid; "
                            + "other vendors add rsa_pss_saltlen or fc_n");
            check("C6d", "crypto", orderOk(sign.json, SIGN_KEYS) ? "pass" : "warn",
                    "the wire spells the keys in the stock order",
                    "orderOk=" + orderOk(sign.json, SIGN_KEYS)
                            + " firstKeys=" + leadingKeys(sign.json, 4),
                    "the SDK parses by name, but the order pins the backend");
            check("C7", "crypto", challenge.equals(sign.obj.optString("raw")) ? "pass" : "fail",
                    "the signed body carries the challenge verbatim",
                    "raw=" + sign.obj.optString("raw") + " expectedLen=" + challenge.length(), "");
            check("C8", "crypto", "info", "record TEE and fingerprint identity",
                    "tee_n=" + sign.obj.optString("tee_n") + " tee_v=" + sign.obj.optString("tee_v")
                            + " fp_n=" + sign.obj.optString("fp_n") + " fp_v=" + sign.obj.optString("fp_v")
                            + " saltlen=" + sign.obj.optString("rsa_pss_saltlen"),
                    "stock answers QSEE/5 and fingerprint/1");
            if (authBlob != null) {
                try {
                    boolean ok = Blobs.verifyPssRaw(
                            Blobs.pemToRsaKey(authBlob.obj.getString("pub_key")),
                            sign.body, sign.signature, 20);
                    check("C4", "crypto", ok ? "pass" : "fail",
                            "the sign result verifies with the AuthKey public key",
                            "EMSA-PSS/SHA-256/salt=20 -> " + ok, "");
                } catch (Throwable t) {
                    check("C4", "crypto", "fail", "sign result verify", String.valueOf(t), "");
                }
            }
            if (askBlob != null && authBlob != null) {
                long a = parseLong(askBlob.obj.optString("counter"), -1);
                long b = parseLong(authBlob.obj.optString("counter"), -1);
                long c = parseLong(sign.obj.optString("counter"), -1);
                check("C9", "crypto", a > 0 && b >= a && c >= b ? "pass" : "warn",
                        "counters move forward ASK <= AuthKey <= result",
                        "ask=" + a + " auth=" + b + " sign=" + c, "");
            }
        } else if (sr != null) {
            // No signature product: the chain cannot be verified without one. The
            // page shows the biometric offer for exactly this state, and a click on
            // it runs the same chain with a real fingerprint behind it.
            dump.put("pendingSignature", true);
            check("C0", "crypto", "info", "签名链尚未走完：需要一次真实指纹授权",
                    "finishSign rc=" + sr.resultCode + " len=" + sr.exportDataLength,
                    "按页面上的「调用指纹补全签名链」：自建一次性 AuthKey → 弹指纹 → 再验 C 组");
        }

        // remove our own AuthKey: the client-visible half of the lifecycle
        int rm = svc.removeAuthKey(uid, kname);
        boolean after = svc.hasAuthKey(uid, kname);
        SoterExportResult afterExport = svc.getAuthKey(uid, kname);
        int afterCode = afterExport == null ? 0 : afterExport.resultCode;
        check("T13", "transactions", rm == 0 && !after && afterCode == -6 ? "pass" : "warn",
                "removeAuthKey then hasAuthKey false and getAuthKey -6",
                "rm=" + rm + " hasAuth=" + after + " export=" + describe(afterExport), "");
    }

    private void sdkLevel() {
        try {
            SoterCore.tryToInitSoterBeforeTreble();
            SoterCore.tryToInitSoterTreble(this);
            Thread.sleep(2500);
            boolean nativeSupport = SoterCore.isNativeSupportSoter();
            int type = SoterCore.getSoterCoreType();
            boolean treble = SoterCore.isTrebleServiceConnected();
            String askName = SoterCoreData.getInstance().getAskName();
            boolean fpSupport = SoterCore.isSupportFingerprint(this);
            boolean fpEnrolled = SoterCore.isSystemHasFingerprint(this);
            check("V1", "sdk", nativeSupport && treble ? "pass" : "fail",
                    "the official SDK reports native support and a connected Treble service",
                    "nativeSupport=" + nativeSupport + " coreType=" + type + " treble=" + treble,
                    "askName=" + askName + " fpSupport=" + fpSupport + " fpEnrolled=" + fpEnrolled);
        } catch (Throwable t) {
            check("V1", "sdk", "fail", "SDK local probe", String.valueOf(t), "");
        }
    }

    // ---- report ------------------------------------------------------------------------

    private void check(String id, String group, String status, String expected,
                       String observed, String evidence) {
        try {
            JSONObject o = new JSONObject();
            o.put("id", id);
            o.put("group", group);
            o.put("vantage", "app");
            o.put("status", status);
            o.put("expected", expected);
            o.put("observed", observed);
            o.put("evidence", evidence);
            checks.add(o);
        } catch (Throwable ignored) {
        }
        String line = String.format("%-5s %-12s %-5s %s", id, group, status, observed);
        Log.i(TAG, line);
        synchronized (screen) {
            screen.append(line).append('\n');
        }
        tick(id, group);
    }

    private void persist() {
        try {
            int pass = 0, warn = 0, fail = 0, info = 0;
            for (JSONObject o : checks) {
                String s = o.optString("status");
                if ("pass".equals(s)) pass++;
                else if ("warn".equals(s)) warn++;
                else if ("fail".equals(s)) fail++;
                else info++;
            }
            JSONObject root = new JSONObject();
            root.put("schema", "soterchecker/1");
            root.put("generated_at", System.currentTimeMillis() / 1000L);
            JSONObject app = new JSONObject();
            app.put("pkg", getPackageName());
            app.put("uid", Process.myUid());
            app.put("bind_ms", bindMs);
            root.put("app", app);
            root.put("checks", new JSONArray(checks));
            dump.put("profilesSource", Profiles.source);
            // The judgement travels with the report: an app that can run these checks
            // can also state the verdict without a host or a privileged vantage.
            JSONObject verdict = Verdict.compute(checks, android.os.Build.BRAND,
                    android.os.Build.MANUFACTURER, android.os.Build.VERSION.SDK_INT);
            root.put("verdict", verdict);
            if (dump.length() > 0) {
                root.put("dump", dump);
            }
            JSONObject summary = new JSONObject();
            summary.put("pass", pass);
            summary.put("warn", warn);
            summary.put("fail", fail);
            summary.put("info", info);
            root.put("summary", summary);

            File f = new File(getExternalFilesDir(null), "sotercheck-app.json");
            String text = root.toString(2);
            reportJson = text;
            FileOutputStream out = new FileOutputStream(f);
            out.write(text.getBytes("UTF-8"));
            out.close();
            Log.i(TAG, "report=" + f.getAbsolutePath() + " pass=" + pass + " warn=" + warn
                    + " fail=" + fail + " info=" + info);
            Log.i(TAG, "verdict=" + verdict.optString("state")
                    + " semantics=" + verdict.optString("semantics")
                    + " :: " + verdict.optString("conclusion"));
        } catch (Throwable t) {
            Log.e(TAG, "persist failed", t);
        }
    }

    /** End of run: hand the finished report to the page that is already showing progress. */
    private void showResult() {
        if (webView == null || reportJson == null) {
            finish();
            return;
        }
        reveal(webView);
    }

    /** Injects the report once, whichever of page load and probe end comes last. */
    private void reveal(final WebView view) {
        final String json = reportJson;
        if (json == null || !pageReady || revealed) {
            return;
        }
        revealed = true;
        // The report is a JSON object literal already; quoting it again would
        // hand the page a string instead of the report.
        view.evaluateJavascript("window.renderReport(" + json + ")", null);
    }

    /** Streams one finished check to the progress overlay; no-ops without a page. */
    private void tick(final String id, final String group) {
        runOnUiThread(new Runnable() { @Override public void run() {
            if (webView != null) {
                webView.evaluateJavascript("window.checkTick('" + id + "','" + group + "')", null);
            } else if (tv != null) {
                final String text;
                synchronized (screen) {
                    text = screen.toString();
                }
                tv.setText(text);
            }
        } });
    }

    /** The page-side "调用指纹补全签名链" button lands here. */
    private class FingerprintBridge {
        @JavascriptInterface
        public void requestFingerprint() {
            runOnUiThread(new Runnable() { @Override public void run() {
                startFingerprintChain();
            } });
        }
    }

    /**
     * One biometric signing round for the chain the plain run cannot finish: a
     * throwaway AuthKey, the same compat prompt the SDK uses on the Treble path,
     * then the crypto checks on the result. The report is rebuilt and re-injected,
     * so the page and the verdict move to the completed state without a relaunch.
     */
    private void startFingerprintChain() {
        if (fingerprintRun) {
            return;
        }
        if (svc == null || webView == null || reportJson == null) {
            postToPage("window.fingerprintState('unavailable')");
            return;
        }
        fingerprintRun = true;
        postToPage("window.fingerprintState('waiting')");
        new Thread(new Runnable() { @Override public void run() {
            try {
                runFingerprintChain();
            } catch (Throwable t) {
                check("C10", "crypto", "fail", "指纹补链执行", String.valueOf(t), "");
                Log.e(TAG, "fingerprint chain failed", t);
            } finally {
                fingerprintRun = false;
                persist();
                final String json = reportJson;
                if (json != null) {
                    postToPage("window.renderReport(" + json + ")");
                }
            }
        } }).start();
    }

    /** Runs one script in the page, if there is a page. */
    private void postToPage(final String script) {
        runOnUiThread(new Runnable() { @Override public void run() {
            if (webView != null) {
                webView.evaluateJavascript(script, null);
            }
        } });
    }

    /** Drops the records a previous biometric attempt wrote, so a retry replaces them. */
    private void clearChecks(String... ids) {
        List<String> replaced = Arrays.asList(ids);
        for (Iterator<JSONObject> it = checks.iterator(); it.hasNext(); ) {
            if (replaced.contains(it.next().optString("id"))) {
                it.remove();
            }
        }
    }

    /** The biometric half of the signature chain; every step lands in the report. */
    private void runFingerprintChain() throws Exception {
        final int uid = Process.myUid();
        clearChecks("C0", "C10", "C11", "C12", "C4", "C6c", "C6d", "C7", "C8", "C9");

        String kname = "sotercheck_fp_" + System.currentTimeMillis();
        int gen = svc.generateAuthKey(uid, kname);
        SoterExportResult auth = svc.getAuthKey(uid, kname);
        if (gen != 0 || auth == null || auth.resultCode != 0 || auth.exportData == null) {
            check("C10", "crypto", "fail", "为补链生成一次性 AuthKey",
                    "gen=" + gen + " " + describe(auth), "name=" + kname);
            dump.put("pendingSignature", true);
            return;
        }
        check("C10", "crypto", "pass", "为补链生成一次性 AuthKey（用完即删）",
                "gen=0 len=" + auth.exportDataLength, "name=" + kname);
        Blobs authBlob = Blobs.parse(auth.exportData);

        String challenge = "sotercheck-fp-chal-" + System.currentTimeMillis();
        SoterSessionResult sess = svc.initSigh(uid, kname, challenge);
        if (sess == null || sess.resultCode != 0) {
            check("C11", "crypto", "fail", "initSign rc=0（补链会话）",
                    sess == null ? "null" : ("rc=" + sess.resultCode), "");
            removeQuietly(uid, kname);
            dump.put("pendingSignature", true);
            return;
        }

        Log.i(TAG, "fingerprint prompt is up; waiting up to 120s for a press");
        String prompt = fingerprintPrompt();
        long t0 = System.currentTimeMillis();
        SoterSignResult sr = svc.finishSign(sess.session);
        long dt = System.currentTimeMillis() - t0;
        boolean matched = "matched".equals(prompt);
        check("C11", "crypto", matched ? "pass" : "warn",
                "指纹授权完成（matched）",
                "prompt=" + prompt + " finishRc=" + (sr == null ? "null" : sr.resultCode)
                        + " ms=" + dt,
                matched ? "" : "没按或没匹配时签名链保持待补状态，可重试");
        if (!matched || sr == null || sr.resultCode != 0 || sr.exportData == null) {
            check("C0", "crypto", "info", "签名链仍在等待一次指纹授权",
                    sr == null ? "no sign result" : ("finishSign rc=" + sr.resultCode),
                    "按「重试指纹授权」再走一次即可");
            removeQuietly(uid, kname);
            dump.put("pendingSignature", true);
            return;
        }

        Blobs sign = Blobs.parse(sr.exportData);
        try {
            dump.put("signB64", Base64.encodeToString(sign.blob, Base64.NO_WRAP));
        } catch (Throwable ignored) {
        }
        boolean keysOk = keysMatch(sign.obj, SIGN_KEYS);
        boolean onlyVendorExtras = keysOk || extraKeysAreVendorOptional(sign.obj);
        check("C6c", "crypto", keysOk ? "pass" : (onlyVendorExtras ? "info" : "warn"),
                "result keys exactly " + Arrays.toString(SIGN_KEYS),
                "keys=" + keysOf(sign.obj) + " " + keyDiff(sign.obj, SIGN_KEYS),
                "biometric run: rc=0 len=" + sr.exportDataLength);
        check("C6d", "crypto", orderOk(sign.json, SIGN_KEYS) ? "pass" : "warn",
                "the wire spells the keys in the stock order",
                "orderOk=" + orderOk(sign.json, SIGN_KEYS)
                        + " firstKeys=" + leadingKeys(sign.json, 4), "");
        check("C7", "crypto", challenge.equals(sign.obj.optString("raw")) ? "pass" : "fail",
                "the signed body carries the challenge verbatim",
                "raw=" + sign.obj.optString("raw"), "");
        check("C8", "crypto", "info", "record TEE and fingerprint identity",
                "tee_n=" + sign.obj.optString("tee_n") + " tee_v=" + sign.obj.optString("tee_v")
                        + " fp_n=" + sign.obj.optString("fp_n") + " fp_v=" + sign.obj.optString("fp_v")
                        + " saltlen=" + sign.obj.optString("rsa_pss_saltlen"), "");
        try {
            boolean ok = Blobs.verifyPssRaw(
                    Blobs.pemToRsaKey(authBlob.obj.getString("pub_key")),
                    sign.body, sign.signature, 20);
            check("C4", "crypto", ok ? "pass" : "fail",
                    "the sign result verifies with the AuthKey public key",
                    "EMSA-PSS/SHA-256/salt=20 -> " + ok, "");
        } catch (Throwable t) {
            check("C4", "crypto", "fail", "sign result verify", String.valueOf(t), "");
        }
        Blobs askBlob = null;
        String askB64 = dump.optString("askB64", "");
        if (!askB64.isEmpty()) {
            try {
                askBlob = Blobs.parse(Base64.decode(askB64, Base64.NO_WRAP));
            } catch (Throwable ignored) {
            }
        }
        if (askBlob != null) {
            long a = parseLong(askBlob.obj.optString("counter"), -1);
            long b = parseLong(authBlob.obj.optString("counter"), -1);
            long c = parseLong(sign.obj.optString("counter"), -1);
            check("C9", "crypto", a > 0 && b >= a && c >= b ? "pass" : "warn",
                    "counters move forward ASK <= AuthKey <= result",
                    "ask=" + a + " auth=" + b + " sign=" + c, "");
        }

        int rm = svc.removeAuthKey(uid, kname);
        boolean after = svc.hasAuthKey(uid, kname);
        check("C12", "crypto", rm == 0 && !after ? "pass" : "warn",
                "补链用的一次性 AuthKey 已删除", "rm=" + rm + " hasAuth=" + after,
                "name=" + kname);
        dump.put("pendingSignature", false);
    }

    /** Best-effort key cleanup for the failure paths of the biometric run. */
    private void removeQuietly(int uid, String kname) {
        try {
            svc.removeAuthKey(uid, kname);
        } catch (Throwable ignored) {
        }
    }

    // ---- helpers -----------------------------------------------------------------------

    private static String describe(SoterExportResult r) {
        if (r == null) return "null";
        return "rc=" + r.resultCode + " len=" + r.exportDataLength
                + " data=" + (r.exportData == null ? -1 : r.exportData.length);
    }

    private static String keysOf(JSONObject o) {
        TreeSet<String> keys = new TreeSet<String>();
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            keys.add(it.next());
        }
        return keys.toString();
    }

    private static boolean keysMatch(JSONObject o, String[] want) {
        TreeSet<String> have = new TreeSet<String>();
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            have.add(it.next());
        }
        TreeSet<String> expect = new TreeSet<String>(Arrays.asList(want));
        return have.equals(expect);
    }

    private static String keyDiff(JSONObject o, String[] want) {
        TreeSet<String> have = new TreeSet<String>();
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            have.add(it.next());
        }
        TreeSet<String> missing = new TreeSet<String>(Arrays.asList(want));
        missing.removeAll(have);
        TreeSet<String> extra = new TreeSet<String>(have);
        extra.removeAll(Arrays.asList(want));
        return "missing=" + missing + " extra=" + extra;
    }

    /** True when every key present is either expected or a known other-vendor key. */
    private static boolean extraKeysAreVendorOptional(JSONObject o) {
        TreeSet<String> allowed = new TreeSet<String>(Arrays.asList(SIGN_KEYS));
        allowed.addAll(Arrays.asList(VENDOR_OPTIONAL_KEYS));
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            if (!allowed.contains(it.next())) {
                return false;
            }
        }
        return true;
    }

    /** The stock TA writes its keys in a fixed order; a JSONObject would hide that. */
    private static boolean orderOk(String json, String[] keys) {
        int at = -1;
        for (String k : keys) {
            int pos = json.indexOf("\"" + k + "\"");
            if (pos < 0 || pos < at) {
                return false;
            }
            at = pos;
        }
        return true;
    }

    private static String leadingKeys(String json, int count) {
        StringBuilder sb = new StringBuilder("[");
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"([^\"]+)\"\\s*:").matcher(json);
        while (m.find() && count > 0) {
            if (sb.length() > 1) {
                sb.append(", ");
            }
            sb.append(m.group(1));
            count--;
        }
        return sb.append(']').toString();
    }

    private static long parseLong(String s, long fallback) {
        try {
            return Long.parseLong(s);
        } catch (Throwable t) {
            return fallback;
        }
    }

    private static String mask(String hex) {
        if (hex == null || hex.length() < 12) return String.valueOf(hex);
        return hex.substring(0, 8) + ".." + hex.substring(hex.length() - 4);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    private static String sha256Hex(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return hex(md.digest(b));
    }

    private static String sha256File(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        FileInputStream in = new FileInputStream(f);
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            md.update(buf, 0, n);
        }
        in.close();
        return hex(md.digest());
    }

    private static byte[] read(FileInputStream in, int max) throws Exception {
        byte[] buf = new byte[max];
        int n = in.read(buf);
        in.close();
        return n <= 0 ? new byte[0] : Arrays.copyOf(buf, n);
    }

    private static String sec() {
        try {
            Class<?> sc = Class.forName("android.os.SELinux");
            Object enforced = sc.getMethod("isSELinuxEnforced").invoke(null);
            return "enforced=" + enforced;
        } catch (Throwable t) {
            return "enforced=?";
        }
    }

    /** One independent way to ask "can I see this package". */
    private interface LeakProbe {
        boolean leaks() throws Throwable;
    }

    /** Runs every probe in isolation: one that throws must not hide the others. */
    private static int sweep(StringBuilder detail, String[] names, LeakProbe[] probes) {
        int leaks = 0;
        for (int i = 0; i < probes.length; i++) {
            try {
                if (probes[i].leaks()) {
                    leaks++;
                    detail.append(names[i]).append(", ");
                }
            } catch (Throwable ignored) {
                // a probe that cannot run at all learned nothing; treat it as blind
            }
        }
        return leaks;
    }

    /** True when the path is one of the sampled vendor layouts. */
    private static boolean isProfilePath(String path) {
        for (String[] p : PROFILES) {
            if (p[1].equals(path)) {
                return true;
            }
        }
        return false;
    }

    /** True when the bytes match one of the sampled vendor APKs. */
    private static boolean isProfileHash(String hash) {
        for (String[] p : PROFILES) {
            if (p[3].length() > 0 && p[3].equals(hash)) {
                return true;
            }
        }
        return false;
    }

    /** The stock APK path this device has: what PM reports first, then the profiles. */
    private static String stockPathFor(String reportedSourceDir) {
        if (reportedSourceDir != null && !reportedSourceDir.isEmpty()
                && !"?".equals(reportedSourceDir)) {
            return reportedSourceDir;
        }
        for (String[] p : PROFILES) {
            if (new File(p[1]).exists()) {
                return p[1];
            }
        }
        return PROFILES[0][1];
    }

    private static String stockDirOf(String apkPath) {
        int cut = apkPath.lastIndexOf('/');
        return cut > 0 ? apkPath.substring(0, cut) : apkPath;
    }

    /** "match" when a sampled profile agrees, "size-only" when its bytes were never readable. */
    private static String profileOf(String path, String hash, long size) {
        for (String[] p : PROFILES) {
            if (!p[1].equals(path)) {
                continue;
            }
            boolean hashKnown = p[3].length() > 0;
            if (hashKnown && p[3].equals(hash)) {
                return "match";
            }
            if (!hashKnown && String.valueOf(size).equals(p[2])) {
                return "size-only";
            }
            return "differs";
        }
        return "unknown-path";
    }


    private static String exec(String cmd) throws Exception {
        java.lang.Process p = Runtime.getRuntime().exec(cmd);
        java.io.BufferedReader br = new java.io.BufferedReader(
                new java.io.InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line).append('\n');
        }
        br.close();
        p.waitFor();
        return sb.toString();
    }

    private static String readText(String path) throws Exception {
        java.io.BufferedReader br = new java.io.BufferedReader(
                new java.io.InputStreamReader(new FileInputStream(path)));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line).append('\n');
        }
        br.close();
        return sb.toString();
    }

}
