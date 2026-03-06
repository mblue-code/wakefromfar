import Foundation

enum AppMessage: Equatable {
    case localized(String)
    case verbatim(String)
}
