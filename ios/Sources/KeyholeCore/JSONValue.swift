import Foundation

/// A JSON value of any shape, used to carry payload fields this build does not
/// know about.
///
/// Swift's `Codable` drops unrecognised keys silently, which is the wrong default
/// for a vault: the iOS app is one of four surfaces reading one synced vault, so a
/// payload written by a newer Keyhole regularly lands here. Dropping its fields
/// would mean that opening the vault on an older iPhone and saving once *destroys*
/// data the desktop or extension wrote. `Entry` and `VaultData` therefore keep an
/// `extras` bag and re-encode it verbatim.
///
/// Integers stay integers. Folding every number into `Double` would round-trip a
/// `1` as `1.0`, and the TypeScript side validates some fields with `z.int()`.
public enum JSONValue: Codable, Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Value is not representable as JSON."
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .double(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

/// A coding key built at runtime, so a decoder can enumerate keys it has no
/// compile-time knowledge of.
struct AnyCodingKey: CodingKey {
    var stringValue: String
    var intValue: Int?

    init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

extension Decoder {
    /// Every key of this object that is not in `known`, decoded as raw JSON.
    func unknownKeys(besides known: Set<String>) throws -> [String: JSONValue] {
        let container = try self.container(keyedBy: AnyCodingKey.self)
        var extras: [String: JSONValue] = [:]
        for key in container.allKeys where !known.contains(key.stringValue) {
            extras[key.stringValue] = try container.decode(JSONValue.self, forKey: key)
        }
        return extras
    }
}

extension KeyedEncodingContainer where Key == AnyCodingKey {
    /// Write carried-over fields back out. Known keys are encoded by the caller.
    mutating func encodeExtras(_ extras: [String: JSONValue]) throws {
        // Sorted so the encoded payload is deterministic for a given vault.
        for key in extras.keys.sorted() {
            guard let value = extras[key] else { continue }
            try encode(value, forKey: AnyCodingKey(stringValue: key))
        }
    }
}
