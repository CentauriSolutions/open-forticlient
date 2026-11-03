// Renders OFTCDocument.icns, the icon for .oftc profile files: a document page
// carrying the OFTC tunnel mark. Run: swift make-document-icon.swift
import AppKit

let here = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
let mark = NSImage(contentsOf: here.appendingPathComponent("oftc-icon.png"))!
let size = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

let page = NSRect(x: 168, y: 76, width: 688, height: 872)
let fold: CGFloat = 170
let radius: CGFloat = 44
let path = NSBezierPath()
path.move(to: NSPoint(x: page.minX + radius, y: page.minY))
path.line(to: NSPoint(x: page.maxX - radius, y: page.minY))
path.curve(to: NSPoint(x: page.maxX, y: page.minY + radius),
           controlPoint1: NSPoint(x: page.maxX - 20, y: page.minY), controlPoint2: NSPoint(x: page.maxX, y: page.minY + 20))
path.line(to: NSPoint(x: page.maxX, y: page.maxY - fold))
path.line(to: NSPoint(x: page.maxX - fold, y: page.maxY))
path.line(to: NSPoint(x: page.minX + radius, y: page.maxY))
path.curve(to: NSPoint(x: page.minX, y: page.maxY - radius),
           controlPoint1: NSPoint(x: page.minX + 20, y: page.maxY), controlPoint2: NSPoint(x: page.minX, y: page.maxY - 20))
path.line(to: NSPoint(x: page.minX, y: page.minY + radius))
path.curve(to: NSPoint(x: page.minX + radius, y: page.minY),
           controlPoint1: NSPoint(x: page.minX, y: page.minY + 20), controlPoint2: NSPoint(x: page.minX + 20, y: page.minY))
path.close()

NSGraphicsContext.saveGraphicsState()
let shadow = NSShadow()
shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
shadow.shadowOffset = NSSize(width: 0, height: -14)
shadow.shadowBlurRadius = 28
shadow.set()
NSColor.white.setFill()
path.fill()
NSGraphicsContext.restoreGraphicsState()
NSColor(calibratedWhite: 0.80, alpha: 1).setStroke()
path.lineWidth = 5
path.stroke()

let corner = NSBezierPath()
corner.move(to: NSPoint(x: page.maxX - fold, y: page.maxY))
corner.line(to: NSPoint(x: page.maxX - fold, y: page.maxY - fold + 30))
corner.curve(to: NSPoint(x: page.maxX - fold + 30, y: page.maxY - fold),
             controlPoint1: NSPoint(x: page.maxX - fold, y: page.maxY - fold + 12),
             controlPoint2: NSPoint(x: page.maxX - fold + 12, y: page.maxY - fold))
corner.line(to: NSPoint(x: page.maxX, y: page.maxY - fold))
corner.close()
NSColor(calibratedWhite: 0.92, alpha: 1).setFill()
corner.fill()
NSColor(calibratedWhite: 0.80, alpha: 1).setStroke()
corner.lineWidth = 5
corner.stroke()

mark.draw(in: NSRect(x: 276, y: 318, width: 472, height: 472))

let label = NSAttributedString(string: "OFTC", attributes: [
    .font: NSFont.systemFont(ofSize: 112, weight: .bold),
    .foregroundColor: NSColor(calibratedRed: 0.04, green: 0.24, blue: 0.62, alpha: 1),
    .kern: 14,
])
let labelSize = label.size()
label.draw(at: NSPoint(x: page.midX - labelSize.width / 2 + 7, y: 170))

NSGraphicsContext.restoreGraphicsState()
let png = rep.representation(using: .png, properties: [:])!
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "/tmp/oftc-document-1024.png"
try! png.write(to: URL(fileURLWithPath: out))
