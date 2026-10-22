import SwiftUI
import AVFoundation

struct QRScanner: UIViewControllerRepresentable {
    var accepts: (String) -> Bool = { $0.hasPrefix("otpauth://totp/") }
    let onScan: (String) -> Void
    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController(); controller.onScan = onScan; controller.accepts = accepts; return controller
    }
    func updateUIViewController(_ controller: ScannerController, context: Context) {}
    static func dismantleUIViewController(_ controller: ScannerController, coordinator: ()) { controller.stop() }
}
final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?
    var accepts: (String) -> Bool = { $0.hasPrefix("otpauth://totp/") }
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "com.john.jjvault.camera", qos: .userInitiated)
    private var preview: AVCaptureVideoPreviewLayer?
    private var finished = false
    override func viewDidLoad() {
        super.viewDidLoad(); view.backgroundColor = .black
        AVCaptureDevice.requestAccess(for: .video) { [weak self] allowed in
            DispatchQueue.main.async {
                guard let self, !self.finished else { return }
                if allowed { self.configure() } else {
                    let label = UILabel(frame: self.view.bounds); label.text = "Allow camera access in Settings to scan QR codes"; label.textColor = .white; label.numberOfLines = 0; label.textAlignment = .center; self.view.addSubview(label)
                }
            }
        }
    }
    private func configure() {
        guard let camera = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back), let input = try? AVCaptureDeviceInput(device: camera) else { return }
        queue.async {
            self.session.beginConfiguration()
            if self.session.canSetSessionPreset(.hd1920x1080) { self.session.sessionPreset = .hd1920x1080 } else { self.session.sessionPreset = .high }
            guard self.session.canAddInput(input) else { self.session.commitConfiguration(); return }
            self.session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard self.session.canAddOutput(output) else { self.session.commitConfiguration(); return }
            self.session.addOutput(output); output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]
            self.session.commitConfiguration()
            DispatchQueue.main.async {
                guard !self.finished else { return }
                let layer = AVCaptureVideoPreviewLayer(session: self.session); layer.videoGravity = .resizeAspectFill; layer.frame = self.view.bounds; self.view.layer.addSublayer(layer); self.preview = layer
            }
            self.session.startRunning()
        }
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewWillDisappear(_ animated: Bool) { super.viewWillDisappear(animated); stop() }
    func stop() { finished = true; queue.async { self.session.stopRunning() } }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !finished, let value = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue, accepts(value) else { return }
        stop(); onScan?(value)
    }
}
