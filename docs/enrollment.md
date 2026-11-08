# Platform enrollment

This guide collects the per-platform trust bootstrap flows for `dance`.

The common starting point for all platforms is the same:

1. download the root certificate from `/enroll/root.pem`
2. install it into the platform trust store
3. restart apps or services that cache trust state

## macOS

Routes:
- `/enroll/macos`
- `/enroll/apple.mobileconfig`

Summary:
- import the root certificate into Keychain Access
- trust it for SSL if macOS does not do so automatically

Typical flow:
1. download the root certificate
2. open it in Keychain Access
3. import into the System or login keychain
4. set trust to **Always Trust** if needed
5. restart browsers or local daemons

## iPhone / iPad

Routes:
- `/enroll/ios`
- `/enroll/apple.mobileconfig`

Summary:
- install the downloaded certificate/profile
- enable full trust for the installed root

Typical flow:
1. download the root certificate on the device
2. install it from Settings
3. go to **General → About → Certificate Trust Settings**
4. enable full trust for the installed root CA

## Windows

Routes:
- `/enroll/windows`
- `/enroll/windows.ps1`

Summary:
- import the certificate into **Trusted Root Certification Authorities**

Typical flow:
1. download the root certificate
2. open it and choose **Install Certificate**
3. choose Current User or Local Machine
4. install into **Trusted Root Certification Authorities**
5. restart apps that need the new trust anchor

## Linux

Routes:
- `/enroll/linux`
- `/enroll/linux.sh`

Summary:
- place the certificate in the distro trust store
- refresh trust bundles

Typical flow:
1. download the root certificate
2. copy it into the local CA anchor directory
3. run `update-ca-certificates` or `update-ca-trust`
4. import into NSS separately if Firefox requires it

### First-time HTTPS trust

The Linux helper embeds the configured root certificate and installs it without
fetching it over HTTPS. Download a fresh helper after any root rotation. It returns
404 when no root certificate is available.

Obtain the helper or certificate through a trusted channel and compare the root's
SHA-256 fingerprint with the CA operator before installing it. A script downloaded
through an unverified TLS connection can install an attacker's root or run arbitrary
commands. Do not bypass TLS verification with `curl -k` to bootstrap trust.

For older helpers that fail with `curl: (60)`, obtain a verified copy of
`dance-root-ca.pem` from the operator, then on Debian/Ubuntu run:

```sh
openssl x509 -in dance-root-ca.pem -noout -fingerprint -sha256
# Compare with the fingerprint supplied by the CA operator before continuing.
sudo install -m 0644 dance-root-ca.pem /usr/local/share/ca-certificates/dance-root-ca.crt
sudo update-ca-certificates
```

On Fedora/RHEL, use `/etc/pki/ca-trust/source/anchors/dance-root-ca.crt`
and `sudo update-ca-trust` instead. If HTTPS verification still fails after the
correct issuing root is trusted, check that the server presents its intermediate
certificates and that its certificate covers the requested hostname.

## Downloadable helpers

`dance` now exposes:
- Apple configuration profile: `/enroll/apple.mobileconfig`
- Windows PowerShell helper: `/enroll/windows.ps1`
- Linux shell helper: `/enroll/linux.sh`

These are meant as convenience artifacts for preview/beta deployments.

## Future direction

Still desirable later:
- distro-specific Linux snippets
- Firefox/NSS-specific guidance and automation
- richer device-specific profile customization
