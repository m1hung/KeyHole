import SwiftUI

/// Icon set mirrored from `app/src/components/Icon.tsx`.
///
/// Grammar: 24×24 viewBox · stroke currentColor · width 1.75 · round caps
/// (except `vault`, which is the filled brand mark on a 64×64 canvas).
enum KeyholeIconName: String, CaseIterable {
    case vault
    case key
    case generator
    case settings
    case secureNote
    case localServer
    case copy
    case check
    case eye
    case eyeOff
    case lock
    case user
    case refresh
    case chevronLeft
    case clock
    case plus
    case trash
    case folder
    case folderPlus
}

struct KeyholeIcon: View {
    let name: KeyholeIconName
    var size: CGFloat = 20
    var accessibilityLabel: String? = nil

    var body: some View {
        Group {
            if name == .vault {
                // Asset rendered from docs/brand/logo-mark.svg — avoids Path.subtracting distortion.
                Image("KeyholeMark")
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(1, contentMode: .fit)
                    .frame(width: size, height: size)
            } else {
                Canvas { context, canvasSize in
                    let side = min(canvasSize.width, canvasSize.height)
                    let origin = CGPoint(
                        x: (canvasSize.width - side) / 2,
                        y: (canvasSize.height - side) / 2
                    )
                    let drawRect = CGRect(origin: origin, size: CGSize(width: side, height: side))
                    let path = StrokeIcons.path(for: name, in: drawRect)
                    let lineWidth = 1.75 * (side / 24)
                    context.stroke(
                        path,
                        with: .foreground,
                        style: StrokeStyle(lineWidth: lineWidth, lineCap: .round, lineJoin: .round)
                    )
                }
                .frame(width: size, height: size)
                .aspectRatio(1, contentMode: .fit)
            }
        }
        .accessibilityLabel(accessibilityLabel ?? "")
        .accessibilityHidden(accessibilityLabel == nil)
    }
}

// MARK: - Stroke icons (paths from Icon.tsx)

private enum StrokeIcons {
    static func path(for name: KeyholeIconName, in rect: CGRect) -> Path {
        let sx = rect.width / 24
        let sy = rect.height / 24
        let t = CGAffineTransform(translationX: rect.minX, y: rect.minY).scaledBy(x: sx, y: sy)

        func apply(_ d: String) -> Path {
            SVGPath.parse(d).applying(t)
        }
        func roundRect(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ rx: CGFloat) -> Path {
            Path(roundedRect: CGRect(x: x, y: y, width: w, height: h),
                 cornerSize: CGSize(width: rx, height: rx)).applying(t)
        }

        var path = Path()
        switch name {
        case .vault:
            break
        case .key:
            path.addPath(apply("M12 15.5A4.5 4.5 0 1 1 3 15.5A4.5 4.5 0 0 1 12 15.5Z"))
            path.addPath(apply("M10.7 12.3L21 2"))
            path.addPath(apply("M15.5 7.5l3 3L22 7l-3-3"))
        case .generator:
            path.addPath(apply("M19.5 8A8 8 0 0 0 5 6M5 3v3h3"))
            path.addPath(apply("M4.5 16A8 8 0 0 0 19 18m0 3v-3h-3"))
            path.addPath(apply("M12 8v8m-4-4h8m-6.8-2.8l5.6 5.6m0-5.6l-5.6 5.6"))
        case .settings:
            // Outline gear (hub + 8-tooth ring). Avoids the dense Lucide closed path,
            // which reads as filled at tab-bar sizes when stroked.
            path.addPath(settingsGearPath().applying(t))
        case .secureNote:
            path.addPath(apply("M6 3h8l4 4v4M14 3v4h4M13 21H6V3"))
            path.addPath(roundRect(12, 14, 9, 7, 2))
            path.addPath(apply("M14.5 14v-1.5a2 2 0 0 1 4 0V14m-2 3.5v1"))
        case .localServer:
            path.addPath(roundRect(4, 4, 16, 6, 2))
            path.addPath(roundRect(4, 14, 16, 6, 2))
            path.addPath(apply("M8 7h.01m-.01 10h.01M12 7h5m-5 10h5m-5-7v4"))
        case .copy:
            path.addPath(roundRect(9, 9, 12, 12, 2))
            path.addPath(apply("M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"))
        case .check:
            path.addPath(apply("M20 6L9 17l-5-5"))
        case .eye:
            path.addPath(apply("M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"))
            path.addPath(apply("M15 12A3 3 0 1 1 9 12A3 3 0 0 1 15 12Z"))
        case .eyeOff:
            path.addPath(apply("M10.6 5.1A9.9 9.9 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-2.6 3.6M6.6 6.6A17.2 17.2 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 4.5-1.1"))
            path.addPath(apply("M14.1 14.1a3 3 0 1 1-4.2-4.2"))
            path.addPath(apply("M2 2l20 20"))
        case .lock:
            path.addPath(roundRect(3, 11, 18, 10, 2))
            path.addPath(apply("M7 11V7a5 5 0 0 1 10 0v4"))
        case .user:
            path.addPath(apply("M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"))
            path.addPath(apply("M16 7A4 4 0 1 1 8 7A4 4 0 0 1 16 7Z"))
        case .refresh:
            path.addPath(apply("M21 12a9 9 0 0 1-15.4 6.4L3 16"))
            path.addPath(apply("M3 12a9 9 0 0 1 15.4-6.4L21 8"))
            path.addPath(apply("M21 3v5h-5M3 21v-5h5"))
        case .chevronLeft:
            path.addPath(apply("M15 18l-6-6 6-6"))
        case .clock:
            path.addPath(apply("M21 12A9 9 0 1 1 3 12A9 9 0 0 1 21 12Z"))
            path.addPath(apply("M12 7v5l3 2"))
        case .plus:
            path.addPath(apply("M12 5v14M5 12h14"))
        case .trash:
            path.addPath(apply("M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"))
            path.addPath(apply("M10 11v6M14 11v6"))
        case .folder:
            path.addPath(apply("M3 7v12a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-8l-2-2H5a2 2 0 0 0-2 2z"))
        case .folderPlus:
            path.addPath(apply("M3 7v12a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-8l-2-2H5a2 2 0 0 0-2 2z"))
            path.addPath(apply("M12 12v6M9 15h6"))
        }
        return path
    }

    /// 24×24 outline gear: open hub + ring with eight rectangular teeth.
    private static func settingsGearPath() -> Path {
        var path = Path()
        let center = CGPoint(x: 12, y: 12)
        path.addEllipse(in: CGRect(x: 9, y: 9, width: 6, height: 6))

        let teeth = 8
        let outer: CGFloat = 10.25
        let notch: CGFloat = 8.1
        let toothHalfAngle = CGFloat.pi / CGFloat(teeth) * 0.32
        let step = 2 * CGFloat.pi / CGFloat(teeth)

        func point(radius: CGFloat, angle: CGFloat) -> CGPoint {
            CGPoint(
                x: center.x + radius * cos(angle),
                y: center.y + radius * sin(angle)
            )
        }

        var gear = Path()
        for i in 0..<teeth {
            let mid = -CGFloat.pi / 2 + CGFloat(i) * step
            let a0 = mid - toothHalfAngle
            let a1 = mid + toothHalfAngle
            let gapEnd = mid + step - toothHalfAngle
            if i == 0 {
                gear.move(to: point(radius: outer, angle: a0))
            }
            gear.addLine(to: point(radius: outer, angle: a1))
            gear.addLine(to: point(radius: notch, angle: a1))
            gear.addLine(to: point(radius: notch, angle: gapEnd))
            gear.addLine(to: point(radius: outer, angle: gapEnd))
        }
        gear.closeSubpath()
        path.addPath(gear)
        return path
    }
}

// MARK: - SVG path parser (commands used by Icon.tsx)

private enum SVGPath {
    static func parse(_ d: String) -> Path {
        let tokens = tokenize(d)
        var path = Path()
        var i = 0
        var cx: CGFloat = 0, cy: CGFloat = 0
        var startX: CGFloat = 0, startY: CGFloat = 0
        var lastCmd: Character = "M"
        var prevC2 = CGPoint.zero
        var hasPrevC = false

        func hasNumber() -> Bool {
            i < tokens.count && Double(tokens[i]) != nil
        }
        func read() -> CGFloat {
            let v = CGFloat(Double(tokens[i])!)
            i += 1
            return v
        }

        while i < tokens.count {
            let cmd: Character
            if tokens[i].count == 1, let c = tokens[i].first, c.isLetter {
                cmd = c
                i += 1
            } else {
                switch lastCmd {
                case "M": cmd = "L"
                case "m": cmd = "l"
                default: cmd = lastCmd
                }
            }
            lastCmd = cmd
            let relative = cmd.isLowercase
            let op = Character(cmd.uppercased())

            switch op {
            case "M":
                guard hasNumber() else { continue }
                let x = read(), y = read()
                if relative { cx += x; cy += y } else { cx = x; cy = y }
                startX = cx; startY = cy
                path.move(to: CGPoint(x: cx, y: cy))
                hasPrevC = false
                while hasNumber() {
                    let nx = read(), ny = read()
                    if relative { cx += nx; cy += ny } else { cx = nx; cy = ny }
                    path.addLine(to: CGPoint(x: cx, y: cy))
                }
            case "L":
                while hasNumber() {
                    let x = read(), y = read()
                    if relative { cx += x; cy += y } else { cx = x; cy = y }
                    path.addLine(to: CGPoint(x: cx, y: cy))
                    hasPrevC = false
                }
            case "H":
                while hasNumber() {
                    let x = read()
                    cx = relative ? cx + x : x
                    path.addLine(to: CGPoint(x: cx, y: cy))
                    hasPrevC = false
                }
            case "V":
                while hasNumber() {
                    let y = read()
                    cy = relative ? cy + y : y
                    path.addLine(to: CGPoint(x: cx, y: cy))
                    hasPrevC = false
                }
            case "C":
                while hasNumber() {
                    var x1 = read(), y1 = read(), x2 = read(), y2 = read(), x = read(), y = read()
                    if relative {
                        x1 += cx; y1 += cy; x2 += cx; y2 += cy; x += cx; y += cy
                    }
                    path.addCurve(
                        to: CGPoint(x: x, y: y),
                        control1: CGPoint(x: x1, y: y1),
                        control2: CGPoint(x: x2, y: y2)
                    )
                    prevC2 = CGPoint(x: x2, y: y2)
                    hasPrevC = true
                    cx = x; cy = y
                }
            case "S":
                while hasNumber() {
                    var x2 = read(), y2 = read(), x = read(), y = read()
                    let x1 = hasPrevC ? 2 * cx - prevC2.x : cx
                    let y1 = hasPrevC ? 2 * cy - prevC2.y : cy
                    if relative {
                        x2 += cx; y2 += cy; x += cx; y += cy
                    }
                    path.addCurve(
                        to: CGPoint(x: x, y: y),
                        control1: CGPoint(x: x1, y: y1),
                        control2: CGPoint(x: x2, y: y2)
                    )
                    prevC2 = CGPoint(x: x2, y: y2)
                    hasPrevC = true
                    cx = x; cy = y
                }
            case "Q":
                while hasNumber() {
                    var x1 = read(), y1 = read(), x = read(), y = read()
                    if relative { x1 += cx; y1 += cy; x += cx; y += cy }
                    path.addQuadCurve(to: CGPoint(x: x, y: y), control: CGPoint(x: x1, y: y1))
                    prevC2 = CGPoint(x: x1, y: y1)
                    hasPrevC = true
                    cx = x; cy = y
                }
            case "A":
                while hasNumber() {
                    let rx = abs(read()), ry = abs(read())
                    let rotation = read()
                    let large = read() != 0
                    let sweep = read() != 0
                    var x = read(), y = read()
                    if relative { x += cx; y += cy }
                    addArc(
                        &path,
                        from: CGPoint(x: cx, y: cy),
                        to: CGPoint(x: x, y: y),
                        rx: rx, ry: ry,
                        xAxisRotation: rotation * .pi / 180,
                        largeArc: large, sweep: sweep
                    )
                    cx = x; cy = y
                    hasPrevC = false
                    _ = rotation
                }
            case "Z":
                path.closeSubpath()
                cx = startX; cy = startY
                hasPrevC = false
            default:
                i += 1
            }
        }
        return path
    }

    private static func tokenize(_ d: String) -> [String] {
        var out: [String] = []
        var cur = ""
        func flush() {
            if !cur.isEmpty { out.append(cur); cur = "" }
        }
        for ch in d {
            if ch.isLetter {
                flush()
                out.append(String(ch))
            } else if ch == "," || ch.isWhitespace {
                flush()
            } else if (ch == "-" || ch == "+") && !cur.isEmpty && cur.last != "e" && cur.last != "E" {
                flush()
                cur.append(ch)
            } else if ch == "." && cur.contains(".") {
                flush()
                cur.append(ch)
            } else {
                cur.append(ch)
            }
        }
        flush()
        return out
    }

    /// SVG elliptical arc → cubic approximation (W3C endpoint-to-center).
    private static func addArc(
        _ path: inout Path,
        from: CGPoint,
        to: CGPoint,
        rx rawRx: CGFloat,
        ry rawRy: CGFloat,
        xAxisRotation phi: CGFloat,
        largeArc: Bool,
        sweep: Bool
    ) {
        if from == to { return }
        var rx = rawRx, ry = rawRy
        if rx == 0 || ry == 0 {
            path.addLine(to: to)
            return
        }

        let cosPhi = cos(phi), sinPhi = sin(phi)
        let dx = (from.x - to.x) / 2
        let dy = (from.y - to.y) / 2
        let x1p = cosPhi * dx + sinPhi * dy
        let y1p = -sinPhi * dx + cosPhi * dy

        var rxs = rx * rx, rys = ry * ry
        let x1ps = x1p * x1p, y1ps = y1p * y1p
        let lambda = x1ps / rxs + y1ps / rys
        if lambda > 1 {
            let s = sqrt(lambda)
            rx *= s; ry *= s
            rxs = rx * rx; rys = ry * ry
        }

        let num = max(0, rxs * rys - rxs * y1ps - rys * x1ps)
        let den = rxs * y1ps + rys * x1ps
        var cFactor = (den == 0) ? 0 : sqrt(num / den)
        if largeArc == sweep { cFactor = -cFactor }
        let cxp = cFactor * (rx * y1p) / ry
        let cyp = cFactor * -(ry * x1p) / rx

        let cx = cosPhi * cxp - sinPhi * cyp + (from.x + to.x) / 2
        let cy = sinPhi * cxp + cosPhi * cyp + (from.y + to.y) / 2

        func angle(_ ux: CGFloat, _ uy: CGFloat, _ vx: CGFloat, _ vy: CGFloat) -> CGFloat {
            let sign: CGFloat = (ux * vy - uy * vx < 0) ? -1 : 1
            let dot = ux * vx + uy * vy
            let len = sqrt(ux * ux + uy * uy) * sqrt(vx * vx + vy * vy)
            return sign * acos(min(1, max(-1, len == 0 ? 1 : dot / len)))
        }

        let startVecX = (x1p - cxp) / rx
        let startVecY = (y1p - cyp) / ry
        let endVecX = (-x1p - cxp) / rx
        let endVecY = (-y1p - cyp) / ry
        var theta1 = angle(1, 0, startVecX, startVecY)
        var delta = angle(startVecX, startVecY, endVecX, endVecY)
        if !sweep && delta > 0 { delta -= 2 * .pi }
        if sweep && delta < 0 { delta += 2 * .pi }

        let segments = max(1, Int(ceil(abs(delta) / (CGFloat.pi / 2))))
        let deltaSeg = delta / CGFloat(segments)
        let t = 4 * tan(deltaSeg / 4) / 3

        var a = theta1
        for _ in 0..<segments {
            let b = a + deltaSeg
            let cosA = cos(a), sinA = sin(a)
            let cosB = cos(b), sinB = sin(b)
            let e1 = CGPoint(x: cx + cosPhi * rx * cosA - sinPhi * ry * sinA,
                             y: cy + sinPhi * rx * cosA + cosPhi * ry * sinA)
            let e2 = CGPoint(x: cx + cosPhi * rx * cosB - sinPhi * ry * sinB,
                             y: cy + sinPhi * rx * cosB + cosPhi * ry * sinB)
            let c1 = CGPoint(
                x: e1.x + t * (-cosPhi * rx * sinA - sinPhi * ry * cosA),
                y: e1.y + t * (-sinPhi * rx * sinA + cosPhi * ry * cosA)
            )
            let c2 = CGPoint(
                x: e2.x - t * (-cosPhi * rx * sinB - sinPhi * ry * cosB),
                y: e2.y - t * (-sinPhi * rx * sinB + cosPhi * ry * cosB)
            )
            path.addCurve(to: e2, control1: c1, control2: c2)
            a = b
        }
    }
}
