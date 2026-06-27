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
/// The full app is gated behind a single auto-renewable subscription
/// (`app.codecanic.pro.monthly`) with a 3-day free trial introductory offer.
/// Apple In-App Purchase is the ONLY payment path — required by App Store
/// Review Guideline 3.1.1 for unlocking in-app digital features.
@MainActor
final class SubscriptionManager: ObservableObject {
    static let productID = "app.codecanic.pro.monthly"

    /// Access tier derived from the live StoreKit entitlement.
    /// - `none`: no active subscription → paywall.
    /// - `trial`: active subscription inside the free-trial period (full access).
    /// - `paid`: active, paid subscription (full access).
    enum Tier: String { case none, trial, paid }

    @Published private(set) var product: Product?
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
            let products = try await Product.products(for: [Self.productID])
            product = products.first
        } catch {
            errorMessage = "Couldn't load subscription details. Check your connection and try again."
        }
    }

    /// Resolve the live entitlement into a tier (none/trial/paid). Any active
    /// tier (trial or paid) unlocks the app.
    func refreshEntitlement() async {
        var newTier: Tier = .none
        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result else { continue }
            guard transaction.productID == Self.productID,
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
        guard let product else {
            errorMessage = "Subscription is unavailable right now. Please try again shortly."
            return
        }
        isPurchasing = true
        defer { isPurchasing = false }
        do {
            let result = try await product.purchase()
            switch result {
            case .success(let verification):
                guard case .verified(let transaction) = verification else {
                    errorMessage = "Your purchase couldn't be verified. Please try again."
                    return
                }
                await transaction.finish()
                await refreshEntitlement()
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
                guard case .verified(let transaction) = result else { continue }
                await transaction.finish()
                await self?.refreshEntitlement()
            }
        }
    }

    // MARK: - Display helpers (drive the 3.1.2 disclosures from real product data)

    /// e.g. "$14.99/month" — localized to the user's storefront.
    var priceText: String {
        guard let product else { return "$14.99/month" }
        return "\(product.displayPrice)/month"
    }

    /// e.g. "3 days free, then $14.99/month" — derived from the configured
    /// introductory offer when available, with a safe fallback.
    var offerText: String {
        guard let product,
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

    /// Trial length for button labels, e.g. "3-Day", or nil if the product has
    /// no free-trial introductory offer. Derived from StoreKit so the UI always
    /// matches the duration configured in App Store Connect.
    var trialLengthText: String? {
        guard let intro = product?.subscription?.introductoryOffer,
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

    var body: some View {
        if subs.isLoading {
            ZStack {
                brandBackground.ignoresSafeArea()
                ProgressView().tint(.white).scaleEffect(1.4)
            }
        } else if subs.isSubscribed {
            ContentView().ignoresSafeArea()
        } else {
            PaywallView()
        }
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
                    offerCard
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

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        private let fallbackURL: URL
        private let openExternally: (URL) -> Void
        private var didLoadFallback = false
        weak var webView: WKWebView?

        init(fallbackURL: URL, openExternally: @escaping (URL) -> Void) {
            self.fallbackURL = fallbackURL
            self.openExternally = openExternally
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
            decisionHandler(.allow)
        }
    }
}
