import Foundation

public enum PassphraseWordlist {
    /// BIP-0039 English wordlist (2048 words) loaded from package resources.
    public static let words: [String] = {
        if let url = Bundle.module.url(forResource: "bip39-english", withExtension: "txt"),
           let text = try? String(contentsOf: url, encoding: .utf8)
        {
            return text
                .split(whereSeparator: \.isNewline)
                .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        }
        return []
    }()
}
