package com.andrealyz.soterchecker;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The anti-disguise verdict, computed where the vantage is.
 *
 * The design's ladder lives here so the report carries its own judgement instead
 * of depending on a host-side script: an app that runs these checks can decide
 * "this device has Soter and is pretending it does not" on its own. Privileged
 * facts (hider configuration, the ATTK key, dumpsys) only ever add attribution;
 * none of them is a premise.
 *
 * Wording is English on purpose: the JSON is machine-read, and keeping this file
 * ASCII means no build depends on a source encoding flag.
 */
final class Verdict {

    private static final String[] CN_FAMILIES = {
            "coloros/oplus", "hyperos/miui", "originos/vivo", "magicos/honor", "harmonyos/huawei"
    };
    private static final Map<String, String[]> LABEL_TO_FAMILY = new HashMap<String, String[]>();

    static {
        LABEL_TO_FAMILY.put("coloros/oplus", new String[]{"oppo", "oneplus", "realme"});
        LABEL_TO_FAMILY.put("hyperos/miui", new String[]{"xiaomi", "redmi", "poco"});
        LABEL_TO_FAMILY.put("originos/vivo", new String[]{"vivo", "iqoo"});
        LABEL_TO_FAMILY.put("magicos/honor", new String[]{"honor", "hihonor"});
        LABEL_TO_FAMILY.put("harmonyos/huawei", new String[]{"huawei"});
    }

    /** id -> check it reads; D12 has no check of its own, it sums the T/C groups. */
    private static final String[][] DIM_SPECS = {
            {"D1", "S1"}, {"D2", "S4"}, {"D3", "X3"}, {"D4", "X4"}, {"D5", "X5"},
            {"D6", "X6"}, {"D7", "S5"}, {"D8", "X7"}, {"D9", "X9"}, {"D10", "X10"},
            {"D11", "X11"}, {"D12", ""}, {"D13", "X13"}, {"D14", "X12"},
    };

    private Verdict() {
    }

    private static JSONObject find(List<JSONObject> checks, String id) {
        for (JSONObject c : checks) {
            if (id.equals(c.optString("id"))) {
                return c;
            }
        }
        return null;
    }

    private static String status(List<JSONObject> checks, String id) {
        JSONObject c = find(checks, id);
        return c == null ? "absent" : c.optString("status");
    }

    private static String observed(List<JSONObject> checks, String id) {
        JSONObject c = find(checks, id);
        return c == null ? "" : c.optString("observed");
    }

    private static String field(String text, String key) {
        int at = text.indexOf(key + "=");
        if (at < 0) {
            return "";
        }
        int end = text.indexOf(' ', at);
        return end < 0 ? text.substring(at + key.length() + 1)
                : text.substring(at + key.length() + 1, end);
    }

    private static boolean isCnFamily(String family) {
        for (String f : CN_FAMILIES) {
            if (f.equals(family)) {
                return true;
            }
        }
        return false;
    }

    private static String conclusion(String state, String family, String signer, boolean labelMismatch) {
        switch (state) {
            case "clean":
                return "Clean: the stock Soter component is present and usable from this uid "
                        + "(path readable, component enabled, bindable).";
            case "disguised":
                return "Disguised: the stock Soter component is still here, yet this uid is shown "
                        + "\"no Soter\" - the hiding is active, not the device missing it.";
            case "disguised-by-prior":
                return "Disguised (by firmware prior): every direct channel is blinded on a ROM "
                        + "family (" + family + ") that ships SoterService, so absence is the signal. "
                        + "Medium confidence: no direct evidence left.";
            case "component-mismatch":
                return "Component present but not matching a sampled stock profile (signer "
                        + signer + ") - treated as replaced, not as an honest device.";
            case "semantics-broken":
                return "Visible and bindable, but the transactions answer like a dead or "
                        + "fake TA instead of a living one (not a disguise - the semantics "
                        + "themselves are broken).";
            case "semantics-deviating":
                return "Visible, bindable and mostly right, with a few semantic deviations "
                        + "from the living-TA reference.";
            default:
                return "Cannot self-prove: this uid sees no Soter component and no sampled stock "
                        + "layout, and the firmware family is unknown, so hiding cannot be told "
                        + "apart from a device that genuinely lacks Soter."
                        + (labelMismatch ? " The declared vendor label also disagrees with the "
                        + "ROM's own system packages." : "");
        }
    }

    /** Signal per dimension id, mirroring the host tool's table; names stay with the UI. */
    private static String dimSignal(String id, String st, String obs) {
        switch (id) {
            case "D1":
                return "pass".equals(st) ? "present" : "fail".equals(st) ? "blinded" : "unknown";
            case "D2":
                return "pass".equals(st) ? "usable" : "fail".equals(st) ? "blinded-or-disabled" : "unknown";
            case "D3":
                // A size-only match means the file is there and its size agrees with a
                // sampled layout: the channel answered, so "blinded" would overstate it.
                if (obs != null && obs.contains("profile=size-only")) {
                    return "present";
                }
                return "pass".equals(st) ? "present" : "info".equals(st) ? "blinded" : "unknown";
            case "D4":
            case "D9":
            case "D10":
                return "pass".equals(st) ? "present" : "info".equals(st) ? "blinded" : "unknown";
            case "D5":
                if (obs != null && obs.contains("hits=[")) {
                    return "present";
                }
                return "info".equals(st) ? "informational" : "unknown";
            case "D6":
                return "pass".equals(st) ? "present" : "info".equals(st) ? "unreadable" : "unknown";
            case "D7":
                return "pass".equals(st) ? "enabled" : "fail".equals(st) ? "disabled" : "unknown";
            case "D8":
                return "pass".equals(st) ? "present" : "info".equals(st) ? "weak" : "unknown";
            case "D11":
                return "pass".equals(st) ? "present" : "unknown";
            case "D13":
                return "pass".equals(st) ? "present" : "info".equals(st) ? "limited" : "unknown";
            case "D14":
                return "pass".equals(st) ? "consistent" : "fail".equals(st) ? "forged" : "unknown";
            default:
                return "unknown";
        }
    }

    /**
     * The 14 dimensions this process can judge on its own. D15 (cross-uid) is a
     * host-side comparison, so here it is only declared, not weighed.
     */
    private static JSONArray dimensions(List<JSONObject> checks, String semantics) {
        JSONArray out = new JSONArray();
        try {
            for (String[] spec : DIM_SPECS) {
                String id = spec[0];
                String cid = spec[1];
                boolean summary = "D12".equals(id);
                JSONObject c = summary ? null : find(checks, cid);
                String st = c == null ? "absent" : c.optString("status");
                String signal = summary ? semantics
                        : dimSignal(id, st, c == null ? "" : c.optString("observed"));
                JSONObject d = new JSONObject();
                d.put("id", id);
                d.put("check", summary ? JSONObject.NULL : cid);
                d.put("status", st);
                d.put("signal", signal);
                d.put("observed", c == null ? "" : c.optString("observed"));
                out.put(d);
            }
            JSONObject d15 = new JSONObject();
            d15.put("id", "D15");
            d15.put("check", "witness");
            d15.put("status", "unavailable");
            d15.put("signal", "unavailable");
            d15.put("observed", "");
            out.put(d15);
        } catch (Throwable t) {
            Log.e("SoterChecker", "dimensions failed", t);
        }
        return out;
    }

    /** Builds the verdict object the report carries under "verdict". */
    static JSONObject compute(List<JSONObject> checks, String brand, String manufacturer, int sdk) {
        JSONObject out = new JSONObject();
        try {
            String family = "(unknown)";
            JSONObject x7 = find(checks, "X7");
            if (x7 != null) {
                String raw = field(x7.optString("observed"), "family");
                if (!raw.isEmpty()) {
                    family = raw;
                }
            }
            String label = (brand + " " + manufacturer).toLowerCase();
            boolean expected = sdk >= 29 && (isCnFamily(family)
                    || label.contains("oppo") || label.contains("oneplus")
                    || label.contains("realme") || label.contains("xiaomi")
                    || label.contains("redmi") || label.contains("poco")
                    || label.contains("vivo") || label.contains("iqoo")
                    || label.contains("honor") || label.contains("huawei"));
            boolean labelMismatch = isCnFamily(family)
                    && !matchesFamily(family, label);

            boolean pmReports = "pass".equals(status(checks, "S1"))
                    || "pass".equals(status(checks, "S8"));
            boolean visibilityLimited = !"pass".equals(status(checks, "X13"));
            // A PM that reports nothing while this app cannot even enumerate packages is
            // blind, not contradicted: the filter may be an OEM appop the user set, and
            // the blind channel must never be read as the device hiding something.
            boolean pmBlind = visibilityLimited && !pmReports;
            String signer = field(observed(checks, "S6"), "signerSha256");
            boolean signerStock = isStockSigner(signer);
            String profile = field(observed(checks, "X3"), "profile");
            // Presence, seen without PackageManager: a full profile match, a warning that
            // its bytes disagree with one, or a layout whose size agrees while its bytes
            // were never sampled. Only the first two say anything about the content.
            boolean pathEvidence = "pass".equals(status(checks, "X3"))
                    || "warn".equals(status(checks, "X3"))
                    || "size-only".equals(profile);
            boolean dirEvidence = "pass".equals(status(checks, "X4"));
            boolean layoutEvidence = "pass".equals(status(checks, "X10"));
            boolean present = (pmReports && signerStock) || pathEvidence || dirEvidence;

            JSONArray contradictions = new JSONArray();
            if ("fail".equals(status(checks, "X2"))) {
                contradictions.put("PM_reports_installed_but_apk_invisible");
            }
            if ("fail".equals(status(checks, "S5"))) {
                contradictions.put("component_not_enabled");
            }
            if ("fail".equals(status(checks, "S3")) && pmReports) {
                contradictions.put("component_unresolvable_while_package_present");
            }
            if ("fail".equals(status(checks, "S4")) && present) {
                contradictions.put("service_not_bindable");
            }
            if ("0".equals(field(observed(checks, "X1"), "plainQuery"))
                    && !"0".equals(field(observed(checks, "X1"), "withDisabled"))) {
                contradictions.put("component_only_visible_with_disabled_flag");
            }
            if (pathEvidence && !pmReports && !pmBlind) {
                contradictions.put("PM_hidden_while_stock_apk_present");
            }
            if ("fail".equals(status(checks, "X12"))) {
                contradictions.put("layers_disagree_on_filesystem");
            }

            String state;
            if (!pmReports && !pathEvidence && !dirEvidence) {
                // The firmware prior cannot carry a verdict when the PM channel was
                // blinded by this app's own capability: say so instead of guessing.
                state = expected && !pmBlind ? "disguised-by-prior" : "cannot-self-prove";
            } else if (!present) {
                state = "component-mismatch";
            } else if (contradictions.length() > 0) {
                state = "disguised";
            } else {
                state = "clean";
            }

            // Semantics dimension: only meaningful while the component is reachable.
            boolean bound = "pass".equals(status(checks, "S4"));
            int semanticFails = 0;
            int semanticRuns = 0;
            for (JSONObject c : checks) {
                String id = c.optString("id");
                if (id.startsWith("T") || id.startsWith("C")) {
                    semanticRuns++;
                    if ("fail".equals(c.optString("status"))) {
                        semanticFails++;
                    }
                }
            }
            String semantics;
            if (!bound) {
                semantics = "blinded-or-disabled";
            } else if (semanticRuns == 0) {
                semantics = "unknown";
            } else if (semanticFails == 0) {
                semantics = "consistent";
            } else if (semanticFails < 3) {
                semantics = "minor-deviations";
            } else {
                semantics = "inconsistent";
            }

            // "clean" only covers the disguise axis. A component that is visible and
            // bindable but answers like a dead or fake TA is not clean: the word must
            // say so, otherwise a green banner would bury a red semantics row. The
            // breakage is itself a contradiction - the component claims "I am here"
            // while every transaction answers as if no living TA sat behind it. It
            // is appended only after the state ladder, so it cannot flip the verdict
            // to "disguised".
            if ("clean".equals(state)) {
                if ("inconsistent".equals(semantics)) {
                    state = "semantics-broken";
                    contradictions.put("bindable_but_dead_semantics");
                } else if ("minor-deviations".equals(semantics)) {
                    state = "semantics-deviating";
                    contradictions.put("semantics_deviate_from_reference");
                }
            }

            out.put("state", state);
            out.put("visibility_limited", visibilityLimited);
            // Without direct evidence the confidence rests on the prior, and a filtered
            // package list leaves only the declared labels to build that prior from.
            out.put("confidence", present ? "high"
                    : (isCnFamily(family) ? "medium" : "low"));
            out.put("firmware_family_from_packages", family);
            out.put("soter_expected", expected);
            out.put("label_matches_observed_family", !labelMismatch);
            out.put("signer_matches_stock", signerStock);
            out.put("stock_profile", profile);
            out.put("evidence_pm", pmReports);
            out.put("evidence_filesystem", pathEvidence);
            out.put("evidence_directory", dirEvidence);
            out.put("evidence_layout", layoutEvidence);
            out.put("contradictions", contradictions);
            out.put("semantics", semantics);
            out.put("conclusion", conclusion(state, family, signer, labelMismatch));
            out.put("dimensions", dimensions(checks, semantics));
        } catch (Throwable t) {
            Log.e("SoterChecker", "verdict failed", t);
        }
        return out;
    }

    private static boolean isStockSigner(String signer) {
        if (signer == null || signer.isEmpty()) {
            return false;
        }
        for (String[] profile : SoterCheckerActivity.PROFILES) {
            if (profile[4].length() > 0 && profile[4].equals(signer)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesFamily(String family, String label) {
        String[] tokens = LABEL_TO_FAMILY.get(family);
        if (tokens == null) {
            return true;
        }
        for (String token : tokens) {
            if (label.contains(token)) {
                return true;
            }
        }
        return false;
    }
}
