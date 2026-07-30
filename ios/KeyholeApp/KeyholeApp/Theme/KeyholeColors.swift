import SwiftUI
import UIKit

extension Color {
    init(hex: UInt32, opacity: Double = 1) {
        let r = Double((hex >> 16) & 0xff) / 255
        let g = Double((hex >> 8) & 0xff) / 255
        let b = Double(hex & 0xff) / 255
        self.init(.sRGB, red: r, green: g, blue: b, opacity: opacity)
    }

    init(light: Color, dark: Color) {
        self.init(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark ? UIColor(dark) : UIColor(light)
        })
    }
}

/// Cool-slate palette mirrored from `app/src/styles.css`.
enum KeyholeColors {
    static let bg = Color(light: Color(hex: 0xf4f6f8), dark: Color(hex: 0x0d1117))
    static let surface = Color(light: Color(hex: 0xffffff), dark: Color(hex: 0x151b23))
    static let surface2 = Color(light: Color(hex: 0xe9edf2), dark: Color(hex: 0x1e262f))
    static let border = Color(light: Color(hex: 0xd7dee6), dark: Color(hex: 0x2a3341))
    static let text = Color(light: Color(hex: 0x0f172a), dark: Color(hex: 0xe6edf3))
    static let textDim = Color(light: Color(hex: 0x57646f), dark: Color(hex: 0x8b97a6))

    static let accent = Color(light: Color(hex: 0x0f62d0), dark: Color(hex: 0x4d9fff))
    static let accentHover = Color(light: Color(hex: 0x0b4ea8), dark: Color(hex: 0x74b4ff))
    static let accentSoft = Color(light: Color(hex: 0xe7f0fd), dark: Color(hex: 0x14243a))
    static let accentText = Color(light: Color(hex: 0xffffff), dark: Color(hex: 0x06101d))

    static let danger = Color(light: Color(hex: 0xb42318), dark: Color(hex: 0xff7b72))
    static let dangerBg = Color(light: Color(hex: 0xfef3f2), dark: Color(hex: 0x3a1a17))
    static let ok = Color(light: Color(hex: 0x067647), dark: Color(hex: 0x3fb950))
    static let warn = Color(light: Color(hex: 0xb54708), dark: Color(hex: 0xd29922))

    static func strengthColor(score: Int) -> Color {
        switch score {
        case 0, 1: return danger
        case 2: return warn
        default: return ok
        }
    }
}
