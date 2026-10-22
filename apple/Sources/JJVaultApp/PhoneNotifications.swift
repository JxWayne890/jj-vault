import SwiftUI
import UIKit
import UserNotifications

@MainActor final class PhoneNotifications: ObservableObject {
    static let shared = PhoneNotifications()
    @Published var deviceToken = ""
    @Published var status = ""
    func register() async {
        do {
            let allowed = try await UNUserNotificationCenter.current().requestAuthorization(options:[.alert,.sound,.badge])
            guard allowed else {status = "Notifications were not enabled. You can change this in iOS Settings.";return}
            UIApplication.shared.registerForRemoteNotifications()
            status = "Registering this device with Apple Push Notification service…"
        } catch {status = error.localizedDescription}
    }
}
final class JJVaultAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application:UIApplication,didFinishLaunchingWithOptions launchOptions:[UIApplication.LaunchOptionsKey:Any]? = nil)->Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }
    func application(_ application:UIApplication,didRegisterForRemoteNotificationsWithDeviceToken deviceToken:Data) {
        PhoneNotifications.shared.deviceToken = deviceToken.map{String(format:"%02x",$0)}.joined()
        PhoneNotifications.shared.status = "Device registered. Copy the device token to your Mac push configuration."
    }
    func application(_ application:UIApplication,didFailToRegisterForRemoteNotificationsWithError error:Error) {
        PhoneNotifications.shared.status = "Push registration unavailable: " + error.localizedDescription
    }
    func userNotificationCenter(_ center:UNUserNotificationCenter,willPresent notification:UNNotification,withCompletionHandler completionHandler:@escaping(UNNotificationPresentationOptions)->Void) {
        completionHandler([.banner,.sound])
    }
}
