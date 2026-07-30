import Foundation
import UIKit

@MainActor
@Observable
public final class ClipboardController {
    public var secondsRemaining: Int?
    public var lastCopied: String?
    public var toastMessage: String?
    public var error: String?

    private var copiedValue: String?
    private var timer: Timer?
    private var toastTask: Task<Void, Never>?
    private var clearAfterSeconds: Int

    public init(clearAfterSeconds: Int = 30) {
        self.clearAfterSeconds = clearAfterSeconds
    }

    public func updateClearAfter(_ seconds: Int) {
        clearAfterSeconds = seconds
    }

    public func copy(_ value: String, label: String) {
        error = nil
        UIPasteboard.general.string = value
        copiedValue = value
        lastCopied = label
        showToast("Copied \(label)")
        stopTimer()
        guard clearAfterSeconds > 0 else { return }
        var remaining = clearAfterSeconds
        secondsRemaining = remaining
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                remaining -= 1
                if remaining <= 0 {
                    self.clearClipboard()
                } else {
                    self.secondsRemaining = remaining
                }
            }
        }
    }

    public func clearClipboard() {
        if UIPasteboard.general.string == nil || UIPasteboard.general.string == copiedValue {
            UIPasteboard.general.string = ""
        }
        copiedValue = nil
        lastCopied = nil
        stopTimer()
    }

    private func showToast(_ message: String) {
        toastTask?.cancel()
        toastMessage = message
        toastTask = Task {
            try? await Task.sleep(nanoseconds: 1_600_000_000)
            guard !Task.isCancelled else { return }
            toastMessage = nil
        }
    }

    private func stopTimer() {
        timer?.invalidate()
        timer = nil
        secondsRemaining = nil
    }
}
