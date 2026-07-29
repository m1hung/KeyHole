import Foundation

public let SYMBOLS = "!@#$%^&*"
public let MIN_LENGTH = 8
public let MAX_LENGTH = 128

public let DEFAULT_GENERATOR_OPTIONS = GeneratorOptions(
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false
)

private let lowercase = "abcdefghijklmnopqrstuvwxyz"
private let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
private let digits = "0123456789"
private let ambiguous = Set(Array("0O1lI5S8B|`'\""))

private func buildClasses(_ options: GeneratorOptions) -> [String] {
    let classes: [(Bool, String)] = [
        (options.lowercase, lowercase),
        (options.uppercase, uppercase),
        (options.digits, digits),
        (options.symbols, SYMBOLS),
    ]
    return classes
        .filter(\.0)
        .map { _, chars in
            if options.excludeAmbiguous {
                return String(chars.filter { !ambiguous.contains($0) })
            }
            return chars
        }
        .filter { !$0.isEmpty }
}

private func randomIndex(_ max: Int) throws -> Int {
    guard max > 0 else {
        throw KeyholeError.validation("randomIndex requires a positive bound.")
    }
    let limit = (0xffff_ffff / UInt32(max)) * UInt32(max)
    while true {
        let b = KeyholeCrypto.randomBytes(4)
        let value =
            (UInt32(b[0]) << 24)
            | (UInt32(b[1]) << 16)
            | (UInt32(b[2]) << 8)
            | UInt32(b[3])
        if value < limit {
            return Int(value % UInt32(max))
        }
    }
}

private func shuffle<T>(_ items: inout [T]) throws {
    var i = items.count - 1
    while i > 0 {
        let j = try randomIndex(i + 1)
        items.swapAt(i, j)
        i -= 1
    }
}

public func generatePassword(_ options: GeneratorOptions = DEFAULT_GENERATOR_OPTIONS) throws -> String {
    let length = options.length
    guard length >= MIN_LENGTH, length <= MAX_LENGTH else {
        throw KeyholeError.validation("Password length must be an integer between \(MIN_LENGTH) and \(MAX_LENGTH).")
    }
    let classes = buildClasses(options)
    if classes.isEmpty {
        throw KeyholeError.validation("Enable at least one character class.")
    }
    if classes.count > length {
        throw KeyholeError.validation("Password length is shorter than the number of required character classes.")
    }

    let pool = classes.joined()
    var chars: [Character] = []
    for cls in classes {
        let arr = Array(cls)
        chars.append(arr[try randomIndex(arr.count)])
    }
    let poolArr = Array(pool)
    while chars.count < length {
        chars.append(poolArr[try randomIndex(poolArr.count)])
    }
    try shuffle(&chars)
    return String(chars)
}

public func generatorPoolSize(_ options: GeneratorOptions) -> Int {
    buildClasses(options).joined().count
}

public func generatorEntropyBits(_ options: GeneratorOptions) -> Double {
    let poolSize = generatorPoolSize(options)
    if poolSize == 0 || options.length <= 0 { return 0 }
    return Double(options.length) * log2(Double(poolSize))
}

public func generatePassphrase(wordlist: [String], words: Int = 5, separator: String = "-") throws -> String {
    if wordlist.count < 128 {
        throw KeyholeError.validation("Wordlist is too small to be useful.")
    }
    if words < 3 || words > 24 {
        throw KeyholeError.validation("Passphrase length must be between 3 and 24 words.")
    }
    var parts: [String] = []
    for _ in 0..<words {
        parts.append(wordlist[try randomIndex(wordlist.count)])
    }
    return parts.joined(separator: separator)
}

public struct StrengthResult: Sendable {
    public var bits: Double
    public var score: Int
    public var label: String
    public var crackTimeDisplay: String

    public init(bits: Double, score: Int, label: String, crackTimeDisplay: String) {
        self.bits = bits
        self.score = score
        self.label = label
        self.crackTimeDisplay = crackTimeDisplay
    }
}

public func estimateStrength(_ password: String) -> StrengthResult {
    if password.isEmpty {
        return StrengthResult(bits: 0, score: 0, label: "very weak", crackTimeDisplay: "instantly")
    }
    return strengthFromBits(entropyBits(password))
}

public func strengthFromBits(_ rawBits: Double) -> StrengthResult {
    let bits = (max(rawBits, 0) * 10).rounded() / 10
    let (score, label) = classify(bits)
    return StrengthResult(bits: bits, score: score, label: label, crackTimeDisplay: crackTime(bits))
}

private let sequences = try! NSRegularExpression(
    pattern: #"(?:abc|bcd|cde|def|123|234|345|456|567|678|789|qwe|wer|ert|asd)"#,
    options: .caseInsensitive
)

private func entropyBits(_ password: String) -> Double {
    if let repeated = try? NSRegularExpression(pattern: #"^(.+?)\1+$"#),
       let match = repeated.firstMatch(in: password, range: NSRange(password.startIndex..., in: password)),
       match.numberOfRanges >= 2,
       let unitRange = Range(match.range(at: 1), in: password)
    {
        let unit = String(password[unitRange])
        return entropyBits(unit) + log2(Double(password.count) / Double(unit.count))
    }

    var poolSize = 0
    if password.range(of: "[a-z]", options: .regularExpression) != nil { poolSize += 26 }
    if password.range(of: "[A-Z]", options: .regularExpression) != nil { poolSize += 26 }
    if password.range(of: "[0-9]", options: .regularExpression) != nil { poolSize += 10 }
    if password.range(of: "[^a-zA-Z0-9]", options: .regularExpression) != nil { poolSize += 33 }

    var bits = Double(password.count) * log2(Double(max(poolSize, 2)))
    let unique = Set(password).count
    if unique <= 2 {
        bits *= 0.35
    } else if Double(unique) / Double(password.count) < 0.4 {
        bits *= 0.65
    }
    if sequences.firstMatch(in: password, range: NSRange(password.startIndex..., in: password)) != nil {
        bits *= 0.75
    }
    return bits
}

private func classify(_ bits: Double) -> (Int, String) {
    if bits < 28 { return (0, "very weak") }
    if bits < 40 { return (1, "weak") }
    if bits < 60 { return (2, "fair") }
    if bits < 80 { return (3, "strong") }
    return (4, "excellent")
}

private func crackTime(_ bits: Double) -> String {
    let seconds = pow(2, bits - 1) / 1e11
    if seconds < 1 { return "instantly" }
    let units: [(Double, String)] = [
        (60, "seconds"),
        (60, "minutes"),
        (24, "hours"),
        (365, "days"),
        (1000, "years"),
    ]
    var value = seconds
    var unit = "seconds"
    for (factor, nextUnit) in units {
        if value < factor { break }
        value /= factor
        unit = nextUnit
    }
    if unit == "years", value >= 1000 {
        return "longer than the age of the universe"
    }
    if value < 10 {
        return String(format: "%.1f %@", value, unit)
    }
    return "\(Int(value.rounded())) \(unit)"
}
