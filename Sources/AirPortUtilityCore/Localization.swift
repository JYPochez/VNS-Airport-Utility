import Foundation

/// UI string localization for the app.
///
/// Keys are the English source text itself, so English needs no table and any
/// untranslated string falls back to readable English instead of a symbolic key.
///
/// IMPORTANT: never route protocol text through here. ACP setting keys (`syNm`),
/// backend flags (`--router-mode`), JSON keys, and enum raw values that are
/// persisted or sent to the backend are wire format, not display text.
/// Localizing them corrupts the protocol. When an enum raw value doubles as a
/// label, add a separate `displayName` rather than translating the raw value.
public enum AirPortLocalization {
  /// The `.lproj` bundle matching the user's preferred languages.
  ///
  /// Resolved from `Locale.preferredLanguages` rather than the one-argument
  /// `Bundle.preferredLocalizations(from:)`, because that variant matches
  /// against the *main* bundle's localizations. Those are empty for a
  /// command-line build or a test harness, which silently pins every lookup to
  /// English even when the user's language is French.
  static let bundle: Bundle = {
    let available = Bundle.module.localizations
    let preferred = Bundle.preferredLocalizations(
      from: available, forPreferences: Locale.preferredLanguages)
    for language in preferred {
      if let url = Bundle.module.url(forResource: language, withExtension: "lproj"),
        let bundle = Bundle(url: url)
      {
        return bundle
      }
    }
    return .module
  }()

  /// Looks up `key`, falling back to the key itself when untranslated.
  public static func text(_ key: String) -> String {
    bundle.localizedString(forKey: key, value: key, table: nil)
  }

  /// The resource bundle holding the `.lproj` tables.
  static var resourceBundle: Bundle { .module }

  /// Language codes with a translation table, for diagnostics and tests.
  static var availableLanguages: [String] {
    Bundle.module.localizations.sorted()
  }
}

/// Shorthand for ``AirPortLocalization/text(_:)`` inside this module.
func localized(_ key: String) -> String {
  AirPortLocalization.text(key)
}
