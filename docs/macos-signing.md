# macOS signing and notarization setup

The release workflow signs the Mac app with your **Developer ID** and has Apple **notarize** it, so it opens on any Mac without a Gatekeeper warning. Until the secrets below exist, the workflow simply builds the Mac app unsigned, as before.

You do this once, on your Mac, in about 20 minutes. The private key is created in, and stays in, your login keychain. Its only other copy is the encrypted GitHub secret.

## 1. Developer ID Application certificate

Only the **Account Holder** of the Apple Developer account can create this.

1. Open **Keychain Access**. From the menu bar choose **Keychain Access → Certificate Assistant → Request a Certificate From a Certificate Authority…**
2. Enter your email address and name, leave CA Email blank, choose **Saved to disk**, then **Continue**. This creates a `.certSigningRequest` file and a private key in your login keychain.
3. Go to [developer.apple.com/account](https://developer.apple.com/account) → **Certificates, IDs & Profiles** → **Certificates** → **+**.
4. Choose **Developer ID Application**. Not "Apple Development", and not "Mac App Distribution". Keep the default **G2 Sub-CA**, upload the request file, and download the `.cer`.
5. Double-click the `.cer` to install it. In Keychain Access → **login** → **My Certificates** you should now see **Developer ID Application: Ryan Bibby (TEAMID)**, with a private key under it when you expand it.
6. Right-click that certificate → **Export…** → format **Personal Information Exchange (.p12)**. Give it a strong password and save it as `DeveloperID.p12`.

## 2. App Store Connect API key (for notarization)

1. Go to [App Store Connect](https://appstoreconnect.apple.com) → **Users and Access** → **Integrations** → **App Store Connect API** → **Team Keys**. If you've never used the API, the Account Holder has to click **Request Access** first.
2. Click **+** and name the key `DHCP Options Finder notarization`. **Developer** access is enough.
3. **Download** the `AuthKey_XXXXXXXXXX.p8`. Apple only lets you download it once.
4. Note the **Key ID** shown next to the key, and the **Issuer ID** shown above the list.

## 3. GitHub repository secrets

Go to the repository → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**. Add five secrets:

| Secret | Value | How to get it |
|---|---|---|
| `MACOS_CERT_P12` | the `.p12`, base64-encoded | `base64 -i DeveloperID.p12 \| pbcopy`, then paste |
| `MACOS_CERT_PASSWORD` | the password you set on export | |
| `APPLE_API_KEY_P8` | the contents of the `.p8` file | `pbcopy < AuthKey_XXXXXXXXXX.p8`, then paste |
| `APPLE_API_KEY_ID` | Key ID | e.g. `2X9R4HXF34` |
| `APPLE_API_ISSUER_ID` | Issuer ID | a UUID |

Then move `DeveloperID.p12` and the `.p8` into your password manager, or delete them. The certificate and key stay in your keychain either way.

## 4. Test it without publishing

1. Go to **Actions** → **Release** → **Run workflow**, on `main`. A manual run builds everything but publishes nothing.
2. When it finishes, download the **DHCPOptionsFinder-macos-arm64** artifact, unzip it, and open the app. It should open with no "can't be opened" warning.
3. To check from Terminal:

   ```bash
   spctl --assess --type execute -vv DHCPOptionsFinder.app
   ```

   It should report `accepted` and `source=Notarized Developer ID`.

The next release, which happens when a version bump merges to `main`, ships the signed app.

## If something fails

| Symptom in the workflow log | Fix |
|---|---|
| `no 'Developer ID Application' certificate with its private key` | The `.p12` was exported without its private key, or it's the wrong certificate type. Re-export from **My Certificates**, not **Certificates**. |
| `security: SecKeychainItemImport: MAC verification failed` | `MACOS_CERT_PASSWORD` doesn't match the `.p12`. |
| Notarization returns `Invalid` | Apple's log is printed right below it, listing each problem file. |
| Notarization `401`/`Unauthorized` | Check the Key ID, the Issuer ID, and that `APPLE_API_KEY_P8` includes the `-----BEGIN PRIVATE KEY-----` lines. |
| The app is notarized but quits right after opening | A hardened-runtime entitlement is missing. Check Console.app for the crash reason and add the entitlement to `.github/macos/entitlements.plist`. |

The Developer ID certificate is valid for 5 years. To rotate it, repeat step 1 and replace the two `MACOS_CERT_*` secrets.
