import SwiftUI

enum KeyholeFonts {
    /// Desktop body is 14px; on iOS use the readable system size that Dynamic Type can scale.
    static let body = Font.system(.body, design: .default)
    static let bodySemibold = Font.system(.body, design: .default).weight(.semibold)
    static let meta = Font.system(.footnote, design: .default)
    static let caption = Font.system(.caption2, design: .default).weight(.semibold)
    static let fieldLabel = Font.system(.caption, design: .default).weight(.semibold)
    static let brand = Font.system(.title2, design: .default).weight(.bold)
    static let detailTitle = Font.system(.title3, design: .default).weight(.semibold)
    static let secret = Font.system(.callout, design: .monospaced)
    static let totp = Font.system(.title3, design: .monospaced).weight(.medium)
    static let error = Font.system(.footnote, design: .default)
}

struct KeyholeFieldLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(KeyholeFonts.fieldLabel)
            .tracking(0.4)
            .foregroundStyle(KeyholeColors.textDim)
            .textCase(.uppercase)
    }
}
