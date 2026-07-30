import SwiftUI
import KeyholeCore

struct KeyholeBrandMark: View {
    var size: CGFloat = 26

    var body: some View {
        KeyholeIcon(name: .vault, size: size)
            .foregroundStyle(KeyholeColors.accent)
            .accessibilityLabel("Keyhole")
    }
}

struct KeyholeCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            content
        }
        .padding(28)
        .frame(maxWidth: 420)
        .background(KeyholeColors.surface)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(KeyholeColors.border, lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.08), radius: 2, y: 1)
        .shadow(color: Color.black.opacity(0.12), radius: 16, y: 8)
    }
}

struct KeyholePrimaryButtonStyle: ButtonStyle {
    var disabled: Bool = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(KeyholeFonts.bodySemibold)
            .foregroundStyle(KeyholeColors.accentText)
            .frame(maxWidth: .infinity, minHeight: 44)
            .padding(.horizontal, 14)
            .background(disabled ? KeyholeColors.accent.opacity(0.45) : KeyholeColors.accent)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .scaleEffect(configuration.isPressed && !disabled ? 0.97 : 1)
            .animation(.easeOut(duration: 0.06), value: configuration.isPressed)
    }
}

struct KeyholeGhostButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(KeyholeFonts.bodySemibold)
            .foregroundStyle(KeyholeColors.accent)
            .frame(minHeight: 44)
            .padding(.horizontal, 14)
            .background(configuration.isPressed ? KeyholeColors.surface2 : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

struct KeyholeLocalBadge: View {
    var body: some View {
        Text("Local vault")
            .font(KeyholeFonts.caption)
            .foregroundStyle(KeyholeColors.accent)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(KeyholeColors.accentSoft)
            .clipShape(Capsule())
    }
}

struct KeyholeStrengthMeter: View {
    let strength: StrengthResult?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(KeyholeColors.surface2)
                        .frame(height: 5)
                    Capsule()
                        .fill(KeyholeColors.strengthColor(score: strength?.score ?? 0))
                        .frame(width: geo.size.width * CGFloat((strength?.score ?? 0) + 1) / 5.0, height: 5)
                        .animation(.spring(response: 0.35, dampingFraction: 0.8), value: strength?.score)
                }
            }
            .frame(height: 5)
            if let strength {
                Text("\(strength.label) · \(String(format: "%.0f", strength.bits)) bits · \(strength.crackTimeDisplay)")
                    .font(KeyholeFonts.meta)
                    .foregroundStyle(KeyholeColors.textDim)
            }
        }
    }
}

struct KeyholeFilterChip: View {
    let title: String
    var count: Int? = nil
    var icon: KeyholeIconName? = nil
    let active: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if let icon {
                    KeyholeIcon(name: icon, size: 12)
                        .foregroundStyle(active ? KeyholeColors.accent : KeyholeColors.textDim)
                }
                Text(title)
                if let count {
                    Text("\(count)")
                        .opacity(0.7)
                }
            }
            .font(KeyholeFonts.caption)
            .foregroundStyle(active ? KeyholeColors.accent : KeyholeColors.textDim)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(active ? KeyholeColors.accentSoft : KeyholeColors.surface2)
            .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}

struct KeyholeToastBanner: View {
    let message: String

    var body: some View {
        Text(message)
            .font(KeyholeFonts.caption)
            .foregroundStyle(KeyholeColors.accentText)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(KeyholeColors.ok)
            .clipShape(Capsule())
            .shadow(color: Color.black.opacity(0.15), radius: 8, y: 4)
            .transition(.move(edge: .top).combined(with: .opacity))
    }
}

struct KeyholeErrorBanner: View {
    let message: String

    var body: some View {
        Text(message)
            .font(KeyholeFonts.error)
            .foregroundStyle(KeyholeColors.danger)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(KeyholeColors.dangerBg)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}
