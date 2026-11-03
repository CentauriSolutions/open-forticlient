// Sets a file's custom Finder icon: set-file-icon ICON.icns FILE...
// The icon is stored on the file (resource fork), outside any signed content.
import AppKit

let arguments = CommandLine.arguments
guard arguments.count >= 3, let icon = NSImage(contentsOfFile: arguments[1]) else {
    FileHandle.standardError.write(Data("usage: set-file-icon ICON.icns FILE...\n".utf8))
    exit(2)
}
for path in arguments.dropFirst(2) {
    guard NSWorkspace.shared.setIcon(icon, forFile: path, options: []) else {
        FileHandle.standardError.write(Data("could not set icon on \(path)\n".utf8))
        exit(1)
    }
}
