import AppKit
import Foundation

let size = 1024
let image = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
let context = NSGraphicsContext(bitmapImageRep: image)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
context.imageInterpolation = .high
NSColor(calibratedRed: 24/255, green: 35/255, blue: 52/255, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(x: 24, y: 24, width: 976, height: 976), xRadius: 216, yRadius: 216).fill()
let shield = NSBezierPath()
shield.move(to: NSPoint(x:512,y:894));shield.line(to:NSPoint(x:798,y:779));shield.line(to:NSPoint(x:774,y:413));shield.curve(to:NSPoint(x:512,y:146),controlPoint1:NSPoint(x:718,y:249),controlPoint2:NSPoint(x:600,y:190));shield.curve(to:NSPoint(x:250,y:413),controlPoint1:NSPoint(x:424,y:190),controlPoint2:NSPoint(x:306,y:249));shield.line(to:NSPoint(x:226,y:779));shield.close()
let top = NSColor(calibratedRed:168/255,green:160/255,blue:255/255,alpha:1)
let bottom = NSColor(calibratedRed:108/255,green:87/255,blue:223/255,alpha:1)
NSGradient(starting:top,ending:bottom)!.draw(in:shield,angle:270)
let text = "JJ" as NSString
let attributes:[NSAttributedString.Key:Any] = [.font:NSFont.systemFont(ofSize:315,weight:.heavy),.foregroundColor:NSColor.white,.kern:-14]
let bounds = text.size(withAttributes:attributes)
text.draw(at:NSPoint(x:(1024-bounds.width)/2,y:425),withAttributes:attributes)
NSGraphicsContext.restoreGraphicsState()
let data = image.representation(using:.png,properties:[:])!
try data.write(to:URL(fileURLWithPath:CommandLine.arguments[1]))
