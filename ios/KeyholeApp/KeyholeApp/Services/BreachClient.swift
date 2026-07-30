import Foundation
import KeyholeCore

enum BreachClient {
    private static let rangeURL = "https://api.pwnedpasswords.com/range"

    /// Opt-in HIBP range lookup. Only a 5-character hash prefix leaves the device.
    static func checkPasswordBreachCount(_ password: String) async throws -> Int {
        let query = hashForRangeQuery(password)
        guard let url = URL(string: "\(rangeURL)/\(query.prefix)") else {
            throw BreachClientError("Invalid Have I Been Pwned URL.")
        }
        var request = URLRequest(url: url)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw BreachClientError("Have I Been Pwned returned an unexpected response.")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw BreachClientError("Have I Been Pwned returned HTTP \(http.statusCode).")
        }
        let body = String(decoding: data, as: UTF8.self)
        return countFromRangeResponse(body, suffix: query.suffix)
    }
}

struct BreachClientError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct BreachHit: Identifiable, Equatable {
    var id: String { entryId }
    var entryId: String
    var title: String
    var count: Int
}
