# Platform enrollment

This guide collects the per-platform trust bootstrap flows for `dance`.

The common starting point for all platforms is the same:

1. download the root certificate from `/enroll/root.pem`
2. install it into the platform trust store
3. restart apps or services that cache trust state

## macOS

Route:
- `/enroll/macos`

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

Route:
- `/enroll/ios`

Summary:
- install the downloaded certificate/profile
- enable full trust for the installed root

Typical flow:
1. download the root certificate on the device
2. install it from Settings
3. go to **General → About → Certificate Trust Settings**
4. enable full trust for the installed root CA

## Windows

Route:
- `/enroll/windows`

Summary:
- import the certificate into **Trusted Root Certification Authorities**

Typical flow:
1. download the root certificate
2. open it and choose **Install Certificate**
3. choose Current User or Local Machine
4. install into **Trusted Root Certification Authorities**
5. restart apps that need the new trust anchor

## Linux

Route:
- `/enroll/linux`

Summary:
- place the certificate in the distro trust store
- refresh trust bundles

Typical flow:
1. download the root certificate
2. copy it into the local CA anchor directory
3. run `update-ca-certificates` or `update-ca-trust`
4. import into NSS separately if Firefox requires it

## Future direction

The current implementation provides human-readable enrollment pages.

Planned next steps:
- Apple configuration profiles / `mobileconfig`
- downloadable Windows helper scripts
- distro-specific Linux snippets
- Firefox/NSS-specific guidance and automation
