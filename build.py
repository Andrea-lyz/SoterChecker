#!/usr/bin/env python3
"""Build SoterChecker, the local Soter-semantics detector APK.

The app is one WebView activity plus the check engine, so it needs no Gradle:
just an Android SDK (one platform, build-tools) and a JDK 17. The SDK lookup and
the tool names below work on Windows and Linux, which is why the same command
builds locally and in CI:

    python build.py                                   -> build/soterchecker-signed.apk
    python build.py --out SoterChecker-1.0            -> build/SoterChecker-1.0-signed.apk
    python build.py --rename-package com.example.copy  -> a sibling install with its own uid

Signing uses the bundled debug keystore on purpose: the app is a diagnostic
tool, it asks for no privileged permission, and one key for local and CI builds
means every later build installs over the previous one.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
CLASSES = BUILD / "classes"
DEX = BUILD / "dex"
KEYSTORE = ROOT / "debug.keystore"
KEYSTORE_PASS = "android"
KEY_ALIAS = "androiddebugkey"
SDK_PLATFORM = "android-36"
BUILD_TOOLS = "36.0.0"
MIN_SDK = "29"
TARGET_SDK = "34"


def fail(message: str) -> "None":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list) -> None:
    printable = " ".join(str(part) for part in command)
    print("+", printable)
    if subprocess.run([str(part) for part in command]).returncode != 0:
        fail(f"command failed: {printable}")


def find_sdk(explicit: str | None) -> Path:
    candidates = [
        explicit,
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        r"C:\Android\Sdk",
        str(Path.home() / "Android" / "Sdk"),
        "/usr/local/lib/android/sdk",
        str(Path.home() / "Library" / "Android" / "sdk"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_dir():
            return Path(candidate).resolve()
    fail("no Android SDK found; set ANDROID_SDK_ROOT or pass --sdk-root")


def find_platform(sdk: Path) -> Path:
    wanted = sdk / "platforms" / SDK_PLATFORM / "android.jar"
    if wanted.is_file():
        return wanted
    installed = sorted((sdk / "platforms").glob("*/android.jar"))
    if not installed:
        fail(f"no platform installed under {sdk / 'platforms'} (need {SDK_PLATFORM})")
    print(f"note: {SDK_PLATFORM} is not installed, using {installed[-1].parent.name}")
    return installed[-1]


def find_build_tools(sdk: Path) -> Path:
    wanted = sdk / "build-tools" / BUILD_TOOLS
    if wanted.is_dir():
        return wanted
    installed = sorted(path for path in (sdk / "build-tools").glob("*") if path.is_dir())
    if not installed:
        fail(f"no build-tools installed under {sdk / 'build-tools'} (need {BUILD_TOOLS})")
    print(f"note: build-tools {BUILD_TOOLS} is not installed, using {installed[-1].name}")
    return installed[-1]


def hosted_tool(directory: Path, name: str) -> Path:
    """Windows ships .exe/.bat wrappers where Linux ships plain scripts."""
    for candidate in (directory / f"{name}.bat", directory / f"{name}.exe", directory / name):
        if candidate.is_file():
            return candidate
    fail(f"{name} not found under {directory}")


def java_tool(name: str) -> str:
    home = os.environ.get("JAVA_HOME")
    if home:
        candidate = Path(home) / "bin" / f"{name}.exe" if os.name == "nt" \
            else Path(home) / "bin" / name
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(name)
    if not found:
        fail(f"{name} not found; install a JDK 17 and set JAVA_HOME")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the SoterChecker APK.")
    parser.add_argument("--out", default="soterchecker", help="output file stem (default: soterchecker)")
    parser.add_argument("--rename-package", help="rewrite the manifest package (sibling install)")
    parser.add_argument("--sdk-root", help="Android SDK root override")
    args = parser.parse_args()

    sdk = find_sdk(args.sdk_root)
    platform = find_platform(sdk)
    build_tools = find_build_tools(sdk)
    aapt2 = hosted_tool(build_tools, "aapt2")
    d8 = hosted_tool(build_tools, "d8")
    zipalign = hosted_tool(build_tools, "zipalign")
    apksigner = hosted_tool(build_tools, "apksigner")
    javac = java_tool("javac")
    print(f"sdk={sdk} platform={platform.parent.name} build-tools={build_tools.name}")

    shutil.rmtree(BUILD, ignore_errors=True)
    CLASSES.mkdir(parents=True)
    DEX.mkdir(parents=True)

    base = BUILD / "base.apk"
    link = [
        aapt2, "link", "-o", base,
        "--manifest", ROOT / "AndroidManifest.xml",
        "-I", platform,
        "-A", ROOT / "assets",
        "--min-sdk-version", MIN_SDK,
        "--target-sdk-version", TARGET_SDK,
    ]
    if args.rename_package:
        link += ["--rename-manifest-package", args.rename_package]
    run(link)

    sources = sorted(str(path) for path in (ROOT / "src").rglob("*.java"))
    sources += sorted(str(path) for path in (ROOT / "gen").rglob("*.java"))
    if not sources:
        fail("no Java sources found")
    run([javac, "-nowarn", "-source", "17", "-target", "17", "-cp", platform, "-d", CLASSES] + sources)

    jar = BUILD / "classes.jar"
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(CLASSES.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(CLASSES).as_posix())

    run([d8, "--lib", platform, "--min-api", MIN_SDK, "--output", DEX, jar])

    unsigned = BUILD / f"{args.out}-unsigned.apk"
    shutil.copyfile(base, unsigned)
    with zipfile.ZipFile(unsigned, "a") as archive:
        # Deflate the dex explicitly: ZipFile.write would store it uncompressed
        # and double the size of the package.
        entry = zipfile.ZipInfo("classes.dex", date_time=(1980, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = 0o644 << 16
        archive.writestr(entry, (DEX / "classes.dex").read_bytes())

    aligned = BUILD / f"{args.out}-aligned.apk"
    run([zipalign, "-f", "-p", "4", unsigned, aligned])

    signed = BUILD / f"{args.out}-signed.apk"
    run([
        apksigner, "sign",
        "--ks", KEYSTORE,
        "--ks-pass", f"pass:{KEYSTORE_PASS}",
        "--key-pass", f"pass:{KEYSTORE_PASS}",
        "--ks-key-alias", KEY_ALIAS,
        "--out", signed,
        aligned,
    ])
    print(f"wrote {signed} ({signed.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
