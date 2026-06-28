import SwiftUI

@main
struct CodecanicApp: App {
    @StateObject private var subscriptions = SubscriptionManager()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(subscriptions)
        }
    }
}
