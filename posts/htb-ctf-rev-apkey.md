# HTB APKey — Android APK RE with Frida Hooking

The challenge provides an Android APK with a login screen that takes a name and password. The goal is to retrieve a hidden key inside the app.

## Static Analysis

Decompiling the APK reveals two `EditText` fields for name and password. The main logic is in the `onClick` handler. The function first checks that the name is `"admin"`, then hashes the password and converts it to a hex string, comparing it against a hardcoded value.

If the comparison passes, it calls `c.b.a.b.a` with the result of `c.b.a.g.a()`. Looking at `c.b.a.g.a()`, it's clearly a decryption routine - likely decrypting the flag.

We can just use Frida to call the decryption function directly, skipping the login check entirely.

## Patching the APK

Installing the original APK failed because the target SDK version was too high for the test device. The fix:

1. Unpack the APK with `apktool`
2. Manually lower the `targetSdkVersion` in `AndroidManifest.xml`
3. Repack and sign the APK

## Frida Hook

With the app running on device, the following Frida script calls the decryption function directly:

```javascript
Java.perform(function () {
    let bClass = Java.use("c.b.a.b");
    let gclass = Java.use("c.b.a.g");
    let r0 = gclass.a();
    r0 = bClass.a(r0);
    console.log("Decrypted:", r0);
})
```

`c.b.a.g.a()` retrieves the encrypted data and `c.b.a.b.a()` decrypts it, printing the flag to the Frida console.

**Flag:** `HTB{m0r3_0bfusc4t1on_w0uld_n0t_hurt}`
