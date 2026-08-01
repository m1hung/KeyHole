import SwiftUI
import UIKit

/// Renders a `KeyholeIcon` as a square template `UIImage` for TabView.
@MainActor
enum KeyholeIconImage {
    static func uiImage(name: KeyholeIconName, pointSize: CGFloat = 24) -> UIImage {
        let side = pointSize
        let view = KeyholeIcon(name: name, size: side)
            .foregroundStyle(.black)
            .frame(width: side, height: side)
        let renderer = ImageRenderer(content: view)
        renderer.scale = UIScreen.main.scale
        renderer.proposedSize = ProposedViewSize(width: side, height: side)
        guard let rendered = renderer.uiImage else { return UIImage() }

        // Re-draw into an exact square so UITabBar cannot stretch non-square bitmaps.
        let pixel = CGSize(width: side, height: side)
        let format = UIGraphicsImageRendererFormat.default()
        format.scale = rendered.scale
        format.opaque = false
        let square = UIGraphicsImageRenderer(size: pixel, format: format).image { _ in
            let drawnSize = rendered.size
            let x = (side - drawnSize.width) / 2
            let y = (side - drawnSize.height) / 2
            rendered.draw(in: CGRect(x: x, y: y, width: drawnSize.width, height: drawnSize.height))
        }
        return square.withRenderingMode(.alwaysTemplate)
    }

    static func image(name: KeyholeIconName, size: CGFloat = 24) -> Image {
        Image(uiImage: uiImage(name: name, pointSize: size))
    }
}
