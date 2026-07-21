import SwiftUI
import WebKit
import SafariServices
import StoreKit

private let primaryURL = URL(string: "https://codecanic.app")!
private let fallbackURL = URL(string: "https://codecanic-production.up.railway.app")!

/// Brand background shown behind the web view and on the paywall.
private let brandBackground = Color(red: 0.039, green: 0.055, blue: 0.078) // #0A0E14
/// Codecanic teal accent.
private let brandAccent = Color(red: 0.08, green: 0.72, blue: 0.65)

// MARK: - Subscription (StoreKit 2)

/// StoreKit 2 subscription state for Codecanic.
///
/// The full app is gated behind an auto-renewable subscription — monthly
/// (`app.codecanic.pro.monthly`, 3-day free trial introductory offer) or
/// annual (`app.codecanic.pro.yearly`). Either plan unlocks everything.
/// Apple In-App Purchase is the ONLY payment path — required by App Store
/// Review Guideline 3.1.1 for unlocking in-app digital features.
@MainActor
final class SubscriptionManager: ObservableObject {
    static let productID = "app.codecanic.pro.monthly"
    static let yearlyProductID = "app.codecanic.pro.yearly"

    /// Access tier derived from the live StoreKit entitlement.
    /// - `none`: no active subscription → paywall.
    /// - `trial`: active subscription inside the free-trial period (full access).
    /// - `paid`: active, paid subscription (full access).
    enum Tier: String { case none, trial, paid }

    /// Which subscription the paywall CTA will buy.
    enum Plan { case monthly, yearly }

    @Published private(set) var product: Product?        // monthly
    @Published private(set) var yearlyProduct: Product?  // annual (nil until approved/available)
    /// Annual is pre-selected — the anchor that makes the yearly price read as
    /// the obvious value. Falls back to monthly when yearly isn't offered.
    @Published var selectedPlan: Plan = .yearly
    @Published private(set) var isSubscribed = false
    @Published private(set) var tier: Tier = .none
    @Published private(set) var isLoading = true
    @Published private(set) var isPurchasing = false
    @Published var errorMessage: String?

    private var updatesTask: Task<Void, Never>?

    init() {
        // Catch transactions that happen outside the app (renewals, Ask-to-Buy
        // approvals, restores on other devices).
        updatesTask = listenForTransactions()
        Task {
            await loadProducts()
            await refreshEntitlement()
            isLoading = false
        }
    }

    deinit { updatesTask?.cancel() }

    func loadProducts() async {
        do {
            let products = try await Product.products(for: [Self.productID, Self.yearlyProductID])
            product = products.first { $0.id == Self.productID }
            yearlyProduct = products.first { $0.id == Self.yearlyProductID }
        } catch {
            errorMessage = "Couldn't load subscription details. Check your connection and try again."
        }
        // Yearly not live (yet, or pulled) → the paywall quietly offers monthly only.
        if yearlyProduct == nil { selectedPlan = .monthly }
    }

    /// The product the CTA will buy.
    var selectedProduct: Product? {
        selectedPlan == .yearly ? (yearlyProduct ?? product) : product
    }

    /// "Save 37%" chip value: how much the annual plan saves vs 12 months of
    /// monthly, computed from the live store prices so a reprice never lies.
    var yearlySavingsPercent: Int? {
        guard let m = product?.price, let y = yearlyProduct?.price, m > 0 else { return nil }
        let full = m * 12
        guard full > y else { return nil }
        let pct = (full - y) / full * 100
        return Int((pct as NSDecimalNumber).doubleValue.rounded())
    }

    /// Resolve the live entitlement into a tier (none/trial/paid). Any active
    /// tier (trial or paid) unlocks the app.
    func refreshEntitlement() async {
        var newTier: Tier = .none
        for await result in Transaction.currentEntitlements {
            // StoreKit 2 device verification can fail spuriously for genuine,
            // Apple-processed transactions (notably in the App Store sandbox,
            // which App Review uses). The entitlement is still real, so accept
            // it rather than locking out a paying customer.
            let transaction = result.unsafePayloadValue
            guard transaction.productID == Self.productID || transaction.productID == Self.yearlyProductID,
                  transaction.revocationDate == nil else { continue }
            newTier = isFreeTrial(transaction) ? .trial : .paid
        }
        tier = newTier
        isSubscribed = (newTier != .none)
    }

    /// Whether a verified transaction is currently in the introductory free
    /// trial. Uses the modern `offer` API on iOS 17.2+ and falls back to the
    /// `offerType` API on iOS 16–17.1 (the only intro offer configured is the
    /// free trial, so `.introductory` here always means the trial).
    private func isFreeTrial(_ transaction: StoreKit.Transaction) -> Bool {
        if #available(iOS 17.2, *) {
            return transaction.offer?.paymentMode == .freeTrial
        } else {
            return transaction.offerType == .introductory
        }
    }

    func purchase() async {
        guard let product = selectedProduct else {
            errorMessage = "Subscription is unavailable right now. Please try again shortly."
            return
        }
        isPurchasing = true
        defer { isPurchasing = false }
        do {
            let result = try await product.purchase()
            switch result {
            case .success(let verification):
                // Apple has processed the payment at this point — never surface
                // an error for a successful charge. `.unverified` occurs
                // spuriously in the App Store sandbox, and the transaction it
                // carries is still a real paid transaction.
                let transaction = verification.unsafePayloadValue
                await transaction.finish()
                // Unlock immediately from the purchase result itself instead of
                // re-reading Transaction.currentEntitlements, which can lag the
                // purchase and would briefly strand the buyer on the paywall.
                tier = isFreeTrial(transaction) ? .trial : .paid
                isSubscribed = true
            case .userCancelled:
                break
            case .pending:
                errorMessage = "Your purchase is pending approval and will activate once approved."
            @unknown default:
                break
            }
        } catch {
            errorMessage = "The purchase didn't complete. Please try again."
        }
    }

    /// Guideline 3.1.1 requires a Restore Purchases mechanism.
    func restore() async {
        isPurchasing = true
        defer { isPurchasing = false }
        do {
            try await AppStore.sync()
            await refreshEntitlement()
            if !isSubscribed {
                errorMessage = "No active subscription was found to restore."
            }
        } catch {
            errorMessage = "Couldn't restore purchases. Please try again."
        }
    }

    private func listenForTransactions() -> Task<Void, Never> {
        Task.detached { [weak self] in
            for await result in Transaction.updates {
                // Finish unverified transactions too (see refreshEntitlement) —
                // leaving them unfinished makes StoreKit redeliver them forever.
                await result.unsafePayloadValue.finish()
                await self?.refreshEntitlement()
            }
        }
    }

    // MARK: - Display helpers (drive the 3.1.2 disclosures from real product data)

    /// e.g. "$14.99/month" or "$99.99/year" — localized to the user's
    /// storefront and matching the currently selected plan.
    var priceText: String {
        guard let product = selectedProduct else { return "$14.99/month" }
        let unit = (selectedPlan == .yearly && yearlyProduct != nil) ? "year" : "month"
        return "\(product.displayPrice)/\(unit)"
    }

    /// e.g. "3 days free, then $14.99/month" — derived from the configured
    /// introductory offer when available, with a safe fallback.
    var offerText: String {
        guard let product = selectedProduct,
              let intro = product.subscription?.introductoryOffer,
              intro.paymentMode == .freeTrial else {
            return "Then \(priceText)"
        }
        let n = intro.period.value
        let unit: String
        switch intro.period.unit {
        case .day:   unit = n == 1 ? "day" : "days"
        case .week:  unit = n == 1 ? "week" : "weeks"
        case .month: unit = n == 1 ? "month" : "months"
        case .year:  unit = n == 1 ? "year" : "years"
        @unknown default: unit = "days"
        }
        return "\(n) \(unit) free, then \(priceText)"
    }

    /// Trial length for button labels, e.g. "3-Day", or nil if the selected
    /// plan has no free-trial introductory offer. Derived from StoreKit so the
    /// UI always matches the duration configured in App Store Connect.
    var trialLengthText: String? {
        guard let intro = selectedProduct?.subscription?.introductoryOffer,
              intro.paymentMode == .freeTrial else { return nil }
        let n = intro.period.value
        let unit: String
        switch intro.period.unit {
        case .day:   unit = "Day"
        case .week:  unit = "Week"
        case .month: unit = "Month"
        case .year:  unit = "Year"
        @unknown default: unit = "Day"
        }
        return "\(n)-\(unit)"
    }
}

// MARK: - Root routing (subscription gate in front of the web experience)

/// While entitlements load we show a brief splash; subscribers get the app,
/// everyone else sees the paywall (Apple IAP is the only payment path).
struct RootView: View {
    @EnvironmentObject private var subs: SubscriptionManager
    @Environment(\.requestReview) private var requestReview
    @AppStorage("reviewPromptSessionCount") private var sessionCount = 0
    @AppStorage("reviewPromptLastVersion") private var lastPromptVersion = ""
    @State private var countedThisSession = false

    var body: some View {
        if subs.isLoading {
            ZStack {
                brandBackground.ignoresSafeArea()
                ProgressView().tint(.white).scaleEffect(1.4)
            }
        } else if subs.isSubscribed {
            ContentView().ignoresSafeArea()
                .task { await maybeRequestReview() }
        } else {
            PaywallView()
        }
    }

    /// Ask for a rating only from engaged users: 3rd+ subscribed session,
    /// 30s in (mid-scan, not mid-launch), once per app version. The system
    /// additionally caps delivery at 3 prompts per 365 days.
    private func maybeRequestReview() async {
        guard !countedThisSession else { return }
        countedThisSession = true
        sessionCount += 1
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        guard sessionCount >= 3, lastPromptVersion != version else { return }
        try? await Task.sleep(for: .seconds(30))
        guard !Task.isCancelled else { return }
        lastPromptVersion = version
        requestReview()
    }
}

// MARK: - Paywall (App Store Review Guideline 3.1.2 compliant)

/// Subscription paywall. Shows the subscription name, length, price-per-period,
/// free-trial terms, the auto-renewal disclosure, Restore Purchases, and
/// functional links to the Terms of Use (EULA) and Privacy Policy — all before
/// purchase.
struct PaywallView: View {
    @EnvironmentObject private var subs: SubscriptionManager

    private static let termsURL = URL(string: "https://codecanic.app/terms")!
    private static let privacyURL = URL(string: "https://codecanic.app/privacy")!

    private let benefits = [
        ("magnifyingglass", "Scan your whole stack", "Continuously scan repos and infrastructure for vulnerabilities, drift, and fixable issues."),
        ("doc.text.magnifyingglass", "Clear repair reports", "Prioritized, explained findings — know exactly what's broken and why it matters."),
        ("wrench.and.screwdriver", "One-tap approved fixes", "Review AI-proposed repairs and ship them as pull requests with your approval."),
        ("lock.shield", "Security you can trust", "Catch vulnerable dependencies and risky config before they reach production.")
    ]

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [brandBackground, Color(red: 0.05, green: 0.11, blue: 0.12)],
                startPoint: .top, endPoint: .bottom
            )
            .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 22) {
                    header
                    benefitList
                    planPicker
                    subscribeButton
                    legalDisclosure
                    footerLinks
                }
                // Constrain to a comfortable reading column and center it, so the
                // paywall looks intentional on iPad and Mac instead of stretching
                // edge-to-edge on a large screen.
                .frame(maxWidth: 480)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 24)
                .padding(.vertical, 32)
            }
        }
        .tint(.white)
        .alert("Subscription", isPresented: Binding(
            get: { subs.errorMessage != nil },
            set: { if !$0 { subs.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { subs.errorMessage = nil }
        } message: {
            Text(subs.errorMessage ?? "")
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Image(systemName: "hammer.circle.fill")
                .font(.system(size: 56))
                .foregroundStyle(brandAccent)
                .shadow(color: brandAccent.opacity(0.5), radius: 16)
            Text("Codecanic")
                .font(.system(size: 30, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
            Text("Scan, report, and repair code across your stack")
                .font(.subheadline)
                .foregroundStyle(.white.opacity(0.75))
                .multilineTextAlignment(.center)
        }
        .padding(.top, 8)
    }

    private var benefitList: some View {
        VStack(alignment: .leading, spacing: 16) {
            ForEach(benefits, id: \.0) { icon, title, detail in
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: icon)
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundStyle(brandAccent)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title)
                            .font(.headline)
                            .foregroundStyle(.white)
                        Text(detail)
                            .font(.footnote)
                            .foregroundStyle(.white.opacity(0.7))
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Plan picker — annual anchored first with the save chip; collapses to
    /// the classic single monthly card when the yearly product isn't live in
    /// the store yet. The billed amount stays the most prominent element of
    /// each card (Guideline 3.1.2).
    @ViewBuilder
    private var planPicker: some View {
        if let yearly = subs.yearlyProduct {
            VStack(spacing: 10) {
                planCard(
                    title: "Annual",
                    price: "\(yearly.displayPrice)/year",
                    caption: "Auto-renews yearly. Cancel anytime.",
                    badge: subs.yearlySavingsPercent.map { "BEST VALUE · SAVE \($0)%" },
                    selected: subs.selectedPlan == .yearly
                ) { subs.selectedPlan = .yearly }
                planCard(
                    title: "Monthly",
                    price: subs.product.map { "\($0.displayPrice)/month" } ?? "—",
                    caption: "Auto-renews monthly. Cancel anytime.",
                    badge: nil,
                    selected: subs.selectedPlan == .monthly
                ) { subs.selectedPlan = .monthly }
            }
        } else {
            offerCard
        }
    }

    /// One selectable plan row: price-forward, with an optional value badge.
    @ViewBuilder
    private func planCard(title: String, price: String, caption: String,
                          badge: String?, selected: Bool, onTap: @escaping () -> Void) -> some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 22))
                    .foregroundStyle(selected ? brandAccent : .white.opacity(0.4))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(title).font(.headline).foregroundStyle(.white)
                        if let badge {
                            Text(badge)
                                .font(.system(size: 10, weight: .heavy))
                                .padding(.horizontal, 7).padding(.vertical, 3)
                                .background(brandAccent, in: Capsule())
                                .foregroundStyle(.black)
                        }
                    }
                    Text(caption).font(.caption2).foregroundStyle(.white.opacity(0.6))
                }
                Spacer()
                Text(price)
                    .font(.subheadline.weight(.bold))
                    .foregroundStyle(selected ? brandAccent : .white.opacity(0.85))
            }
            .padding(.horizontal, 16).padding(.vertical, 14)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(Color.white.opacity(selected ? 0.10 : 0.05))
                    .overlay(RoundedRectangle(cornerRadius: 16)
                        .stroke(selected ? brandAccent : Color.white.opacity(0.15), lineWidth: selected ? 1.5 : 1))
            )
        }
        .buttonStyle(.plain)
    }

    private var offerCard: some View {
        VStack(spacing: 6) {
            Text("Codecanic Pro — Monthly")
                .font(.headline)
                .foregroundStyle(.white)
            Text(subs.offerText)
                .font(.title3.weight(.bold))
                .foregroundStyle(.white)
            Text("Auto-renews monthly. Cancel anytime.")
                .font(.caption)
                .foregroundStyle(.white.opacity(0.7))
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.white.opacity(0.08))
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(brandAccent.opacity(0.35), lineWidth: 1))
        )
    }

    private var subscribeButton: some View {
        VStack(spacing: 12) {
            Button {
                Task { await subs.purchase() }
            } label: {
                ZStack {
                    if subs.isPurchasing {
                        ProgressView().tint(.black)
                    } else {
                        Text(startButtonTitle)
                            .font(.headline)
                    }
                }
                .frame(maxWidth: .infinity)
                .frame(height: 54)
            }
            .background(brandAccent, in: RoundedRectangle(cornerRadius: 14))
            .foregroundStyle(.black)
            .disabled(subs.isPurchasing || subs.product == nil)

            Button("Restore Purchases") {
                Task { await subs.restore() }
            }
            .font(.subheadline)
            .foregroundStyle(.white.opacity(0.85))
            .disabled(subs.isPurchasing)
        }
    }

    private var startButtonTitle: String {
        if let trial = subs.trialLengthText {
            return "Start \(trial) Free Trial"
        }
        return "Subscribe — \(subs.priceText)"
    }

    /// Apple-required auto-renewal disclosure.
    private var legalDisclosure: some View {
        Text("""
        Payment is charged to your Apple Account at confirmation of purchase. \
        After any free trial, the subscription automatically renews at \(subs.priceText) \
        unless cancelled at least 24 hours before the end of the current period. \
        Your account is charged for renewal within 24 hours prior to the end of the \
        current period. Manage or cancel your subscription in your Apple Account settings.
        """)
        .font(.caption2)
        .foregroundStyle(.white.opacity(0.55))
        .multilineTextAlignment(.center)
    }

    private var footerLinks: some View {
        HStack(spacing: 18) {
            Link("Terms of Use", destination: Self.termsURL)
            Text("·").foregroundStyle(.white.opacity(0.4))
            Link("Privacy Policy", destination: Self.privacyURL)
        }
        .font(.caption.weight(.medium))
        .foregroundStyle(.white.opacity(0.8))
        .padding(.bottom, 8)
    }
}

// MARK: - Web experience

struct ContentView: View {
    @State private var safariURL: URL?

    var body: some View {
        CodecanicWebView(
            primaryURL: primaryURL,
            fallbackURL: fallbackURL,
            openExternally: { url in
                safariURL = url
            }
        )
        .ignoresSafeArea()
        .sheet(item: Binding(
            get: { safariURL.map(IdentifiableURL.init) },
            set: { safariURL = $0?.url }
        )) { wrapper in
            SafariView(url: wrapper.url)
                .ignoresSafeArea()
        }
    }
}

private struct IdentifiableURL: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

private struct SafariView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> SFSafariViewController {
        let cfg = SFSafariViewController.Configuration()
        cfg.entersReaderIfAvailable = false
        let vc = SFSafariViewController(url: url, configuration: cfg)
        vc.dismissButtonStyle = .close
        return vc
    }

    func updateUIViewController(_ uiViewController: SFSafariViewController, context: Context) {}
}

struct CodecanicWebView: UIViewRepresentable {
    let primaryURL: URL
    let fallbackURL: URL
    let openExternally: (URL) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(fallbackURL: fallbackURL, openExternally: openExternally)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
        configuration.websiteDataStore = .default()

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.allowsLinkPreview = false
        webView.customUserAgent = (webView.value(forKey: "userAgent") as? String ?? "") + " CodecaniciOS/1.2.0"

        let refresh = UIRefreshControl()
        refresh.tintColor = UIColor(red: 0.08, green: 0.72, blue: 0.65, alpha: 1)
        refresh.addTarget(context.coordinator, action: #selector(Coordinator.pullToRefresh(_:)), for: .valueChanged)
        webView.scrollView.refreshControl = refresh
        context.coordinator.webView = webView

        webView.load(URLRequest(url: primaryURL))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
        private let fallbackURL: URL
        private let openExternally: (URL) -> Void
        private var didLoadFallback = false
        private var downloadDestinations: [ObjectIdentifier: URL] = [:]
        weak var webView: WKWebView?

        init(fallbackURL: URL, openExternally: @escaping (URL) -> Void) {
            self.fallbackURL = fallbackURL
            self.openExternally = openExternally
        }

        private func topViewController() -> UIViewController? {
            let windows = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap(\.windows)
            var top = (windows.first { $0.isKeyWindow } ?? windows.first)?.rootViewController
            while let presented = top?.presentedViewController { top = presented }
            return top
        }

        @objc func pullToRefresh(_ sender: UIRefreshControl) {
            webView?.reload()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                sender.endRefreshing()
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            loadFallbackIfNeeded(in: webView)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            loadFallbackIfNeeded(in: webView)
        }

        private func loadFallbackIfNeeded(in webView: WKWebView) {
            guard !didLoadFallback else { return }
            didLoadFallback = true
            webView.load(URLRequest(url: fallbackURL))
        }

        // OAuth pop-ups and target=_blank links: open in Safari sheet so the main WebView keeps wizard state.
        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            if let url = navigationAction.request.url {
                openExternally(url)
            }
            return nil
        }

        // mailto:, tel:, and unsupported schemes — let the system handle them.
        // Off-origin http(s) stays IN the shell on purpose: the GitHub OAuth
        // flow navigates the main frame off-origin and back.
        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }
            let externalSchemes: Set<String> = ["mailto", "tel", "sms", "facetime"]
            if let scheme = url.scheme?.lowercased(), externalSchemes.contains(scheme) {
                UIApplication.shared.open(url, options: [:], completionHandler: nil)
                decisionHandler(.cancel)
                return
            }
            if navigationAction.shouldPerformDownload {
                decisionHandler(.download)
                return
            }
            decisionHandler(.allow)
        }

        // MARK: - JavaScript dialogs
        // WKWebView drops window.alert/confirm/prompt unless the UI delegate
        // implements them — destructive-action confirms (delete repo/scan)
        // would silently do nothing. Every path MUST call the completion
        // handler or WebKit hangs the page.

        func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                     initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
            guard let top = topViewController() else { completionHandler(); return }
            let alert = UIAlertController(title: nil, message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler() })
            top.present(alert, animated: true)
        }

        func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                     initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
            guard let top = topViewController() else { completionHandler(false); return }
            let alert = UIAlertController(title: nil, message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(false) })
            alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler(true) })
            top.present(alert, animated: true)
        }

        func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                     defaultText: String?, initiatedByFrame frame: WKFrameInfo,
                     completionHandler: @escaping (String?) -> Void) {
            guard let top = topViewController() else { completionHandler(nil); return }
            let alert = UIAlertController(title: nil, message: prompt, preferredStyle: .alert)
            alert.addTextField { $0.text = defaultText }
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(nil) })
            alert.addAction(UIAlertAction(title: "OK", style: .default) { [weak alert] _ in
                completionHandler(alert?.textFields?.first?.text ?? defaultText)
            })
            top.present(alert, animated: true)
        }

        // MARK: - Downloads (scan report / SBOM exports)
        // Responses with Content-Disposition: attachment are silently dropped
        // by WKWebView without download handling — export buttons would do
        // nothing. Save to a temp file, then hand to the Files export picker.

        func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
            let disposition = (navigationResponse.response as? HTTPURLResponse)?
                .value(forHTTPHeaderField: "Content-Disposition")?.lowercased() ?? ""
            if disposition.contains("attachment") || !navigationResponse.canShowMIMEType {
                decisionHandler(.download)
            } else {
                decisionHandler(.allow)
            }
        }

        func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
            download.delegate = self
        }

        func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
            download.delegate = self
        }

        func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                      suggestedFilename: String) async -> URL? {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            } catch {
                return nil
            }
            let dest = dir.appendingPathComponent(suggestedFilename)
            downloadDestinations[ObjectIdentifier(download)] = dest
            return dest
        }

        func downloadDidFinish(_ download: WKDownload) {
            guard let dest = downloadDestinations.removeValue(forKey: ObjectIdentifier(download)) else { return }
            let picker = UIDocumentPickerViewController(forExporting: [dest], asCopy: true)
            picker.shouldShowFileExtensions = true
            topViewController()?.present(picker, animated: true)
        }

        func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
            downloadDestinations.removeValue(forKey: ObjectIdentifier(download))
            guard let top = topViewController() else { return }
            let alert = UIAlertController(
                title: "Download Failed",
                message: "The file couldn't be downloaded. Please check your connection and try again.",
                preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default))
            top.present(alert, animated: true)
        }
    }
}
