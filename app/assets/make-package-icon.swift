// Renders the 1024px artwork for OFTCPackage.icns, the icon for the OFTC
// installer package: a white box carrying the OFTC tunnel mark.
// Run: swiftc make-package-icon.swift -o make-package-icon && ./make-package-icon out.png
import AppKit

let here = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
let mark = NSImage(contentsOf: here.appendingPathComponent("oftc-icon.png"))!
let size = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

// Isometric cube of side s whose nearest bottom corner is f.
let s: CGFloat = 330
let h = s * 0.866
let f = NSPoint(x: 512, y: 150)
let l = NSPoint(x: f.x - h, y: f.y + s / 2)
let r = NSPoint(x: f.x + h, y: f.y + s / 2)
let fu = NSPoint(x: f.x, y: f.y + s)
let lu = NSPoint(x: l.x, y: l.y + s)
let ru = NSPoint(x: r.x, y: r.y + s)
let back = NSPoint(x: f.x, y: f.y + 2 * s)

func polygon(_ points: [NSPoint]) -> NSBezierPath {
    let p = NSBezierPath()
    p.move(to: points[0])
    points.dropFirst().forEach { p.line(to: $0) }
    p.close()
    p.lineJoinStyle = .round
    return p
}
let left = polygon([f, l, lu, fu])
let right = polygon([f, r, ru, fu])
let top = polygon([fu, lu, back, ru])

NSGraphicsContext.saveGraphicsState()
let shadow = NSShadow()
shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
shadow.shadowOffset = NSSize(width: 0, height: -16)
shadow.shadowBlurRadius = 30
shadow.set()
NSColor.white.setFill()
polygon([f, l, lu, back, ru, r]).fill()
NSGraphicsContext.restoreGraphicsState()

NSColor.white.setFill(); left.fill()
NSColor(calibratedWhite: 0.86, alpha: 1).setFill(); right.fill()
NSColor(calibratedWhite: 0.95, alpha: 1).setFill(); top.fill()

// Packing tape across the top and down the right face.
let tapeWidth: CGFloat = 0.22
func lerp(_ a: NSPoint, _ b: NSPoint, _ t: CGFloat) -> NSPoint {
    NSPoint(x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t)
}
let tapeColor = NSColor(calibratedRed: 0.62, green: 0.72, blue: 0.90, alpha: 1)
tapeColor.setFill()
polygon([lerp(fu, ru, 0.5 - tapeWidth / 2), lerp(lu, back, 0.5 - tapeWidth / 2),
         lerp(lu, back, 0.5 + tapeWidth / 2), lerp(fu, ru, 0.5 + tapeWidth / 2)]).fill()
NSColor(calibratedRed: 0.55, green: 0.66, blue: 0.86, alpha: 1).setFill()
polygon([lerp(fu, ru, 0.5 - tapeWidth / 2), lerp(fu, ru, 0.5 + tapeWidth / 2),
         lerp(f, r, 0.5 + tapeWidth / 2), lerp(f, r, 0.5 - tapeWidth / 2)]).fill()

NSColor(calibratedWhite: 0.78, alpha: 1).setStroke()
for edge in [polygon([f, l, lu, back, ru, r]), polygon([fu, lu]), polygon([fu, ru]), polygon([f, fu])] {
    edge.lineWidth = 5
    edge.stroke()
}

// The mark on the left face, sheared to its plane.
NSGraphicsContext.saveGraphicsState()
let transform = NSAffineTransform()
transform.transformStruct = NSAffineTransformStruct(
    m11: h, m12: -s / 2, m21: 0, m22: s, tX: l.x, tY: l.y)
transform.concat()
mark.draw(in: NSRect(x: 0.14, y: 0.14, width: 0.72, height: 0.72))
NSGraphicsContext.restoreGraphicsState()

NSGraphicsContext.restoreGraphicsState()
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "/tmp/oftc-package-1024.png"
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
