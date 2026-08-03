# Security and release signing

Release APKs and `packages.adb` are signed by one persistent ECDSA P-256 key. The private key must exist only in the GitHub Actions secret `ZARAP_APK_PRIVATE_KEY`; it must never be committed, uploaded as an artifact or copied to a router.

Create the key once on a trusted offline machine:

```sh
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out zarap-apk-private.pem
openssl pkey -in zarap-apk-private.pem -pubout -out zarap-apk.pem
```

Store the complete contents of `zarap-apk-private.pem` in the Actions secret. Keep a separate encrypted backup. The release workflow derives and publishes only `zarap-apk.pem` and its SHA-256.

Do not replace the key for ordinary releases. Key rotation requires publishing and documenting the new public key before switching the repository signature.

Security reports should be sent privately to the repository owner rather than opened as a public issue when they contain exploitable details or proxy secrets.
