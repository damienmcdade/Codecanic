# Codecanic mobile deployment

The web app is live at https://codecanic.app. Both mobile shells are thin native WebViews pointed at that URL, so every UI/feature update ships automatically — you only need to rebuild the mobile bundles when changing native config (app icon, splash, version bumps, OS target, signing).

## iOS (App Store)

### State in this repo
- Xcode project: `ios/Codecanic/Codecanic.xcodeproj`
- Bundle ID: `com.codecanic.app`
- Marketing version: `1.1.0`, Build: `2`
- Deployment target: iOS 16
- Primary URL: `https://codecanic.app`, fallback: Railway production URL
- WebView features: pull-to-refresh, OAuth popups open in `SFSafariViewController`, external schemes (`mailto:`/`tel:`) hand off to the system
- `Release` build for simulator compiled successfully under Xcode 26.5

### Submit to App Store
1. Open `ios/Codecanic/Codecanic.xcodeproj` in Xcode.
2. In **Signing & Capabilities**, set **Team** to your Apple Developer Program team. Xcode auto-generates the provisioning profile.
3. Pick **Any iOS Device (arm64)** as the destination.
4. **Product → Archive**. When the Organizer opens, click **Distribute App → App Store Connect → Upload**.
5. In App Store Connect (https://appstoreconnect.apple.com):
   - Create the app record (Bundle ID `com.codecanic.app`).
   - Upload screenshots (6.7", 6.5", 5.5" iPhone + 12.9" iPad), an app icon (1024×1024), privacy policy URL (`https://codecanic.app/` — the in-app modal serves as policy), and a description.
   - Set age rating (4+ should fit, no objectionable content).
   - Submit for review.
6. App Review usually responds in 24–72 hours.

### Things to know
- The app uses `WKWebView` only, no Apple-restricted APIs. ATS is set to `NSAllowsArbitraryLoads=false`; codecanic.app is HTTPS so no exemption needed.
- `ITSAppUsesNonExemptEncryption=false` is set, so no annual export-compliance form.
- Google AdSense ads render inside the WebView. Apple's policy permits this for free apps; the in-app Privacy Policy discloses ads.

## Android (Google Play)

### State in this repo
- Capacitor-based wrapper: `android/`
- Package name: `app.codecanic`
- Version code: `2`, Version name: `1.1.0`
- `minSdkVersion`: 24 (Android 7.0+), `compileSdkVersion`: 36
- Primary URL: `https://codecanic.app` (via `capacitor.config.json`)
- **Signed release AAB built locally**: `android/app/build/outputs/bundle/release/app-release.aab` (≈2.9 MB)

### Signing key
A 2048-bit RSA keystore was generated locally:
- File: `android/codecanic-release.keystore`
- Alias: `codecanic`
- Validity: 10000 days
- DN: `CN=Codecanic, OU=Engineering, O=Codecanic, L=City, ST=State, C=US`

Both the keystore and `android/keystore.properties` (which contains the storePassword + keyPassword) are in `.gitignore` and **must not be committed**. **Back them up to a password manager** — losing them means you cannot publish updates to the same Play Store listing ever again.

### Re-build the AAB
```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
export ANDROID_HOME=$HOME/Library/Android/sdk
export PATH=$JAVA_HOME/bin:$PATH
cd android
./gradlew bundleRelease
```
Output: `android/app/build/outputs/bundle/release/app-release.aab`

### Submit to Play Store
1. Open https://play.google.com/console.
2. **Create app** → package `app.codecanic`, declare it's a free app with ads.
3. **App content** — answer privacy / target audience / data safety / ads (yes, AdSense) / content rating questionnaires. The Privacy Policy URL is `https://codecanic.app/` (the in-app modal counts).
4. **Production → Create new release** → upload `app-release.aab`.
5. Fill out store listing (icon 512×512, feature graphic 1024×500, screenshots, description).
6. Submit for review. Google review typically takes a few hours to several days.

### Re-sign updates
Each subsequent release MUST be signed with the same keystore. To bump the version:
1. Edit `android/app/build.gradle` and increment `versionCode` (must be strictly greater than the previous one) and update `versionName`.
2. Re-run `./gradlew bundleRelease`.
3. Upload the new AAB to Play Console under the same track.

## What this session DID NOT do
- **Did NOT** create an Apple Developer Program account, set up an App Store Connect app record, generate iOS provisioning profiles, or upload an `.ipa`. These require your Apple ID + the $99/year membership.
- **Did NOT** create a Google Play Console account, complete the Play data-safety form, or upload the AAB. These require your Google account + the $25 one-time Play Console fee.
- **Did NOT** generate marketing assets (screenshots, feature graphic, app description). You'll do those at submission time.
