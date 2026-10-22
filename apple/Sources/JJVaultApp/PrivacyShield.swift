import UIKit
/// Synchronously covers every app window before iOS takes an app switcher snapshot.
enum PrivacyShield {
    static let tag = 774401
    @MainActor static func cover() {
        for scene in UIApplication.shared.connectedScenes.compactMap({$0 as? UIWindowScene}) {
            for window in scene.windows where window.viewWithTag(tag) == nil {
                let shield = UIView(frame:window.bounds);shield.tag = tag;shield.autoresizingMask = [.flexibleWidth,.flexibleHeight];shield.backgroundColor = .systemBackground
                let label = UILabel();label.text = "JJ Vault is locked";label.font = .preferredFont(forTextStyle:.title2);label.textAlignment = .center;label.translatesAutoresizingMaskIntoConstraints = false;shield.addSubview(label)
                NSLayoutConstraint.activate([label.centerXAnchor.constraint(equalTo:shield.centerXAnchor),label.centerYAnchor.constraint(equalTo:shield.centerYAnchor)])
                window.addSubview(shield)
            }
        }
    }
    @MainActor static func uncover() {
        for scene in UIApplication.shared.connectedScenes.compactMap({$0 as? UIWindowScene}) {for window in scene.windows {window.viewWithTag(tag)?.removeFromSuperview()}}
    }
}
