# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Upgraded
- "Calypsonet Terminal Calypso Crypto Legacy SAM API" to version `0.4.0`.

## [0.4.0] - 2023-11-28
:warning: Major version! Following the migration of the "Calypsonet Terminal" APIs to the
[Eclipse Keypop project](https://keypop.org), this library now implements Keypop interfaces.
### Added
- Added dependency to "Keypop Calypso Crypto Symmetric API" `0.1.0`
- Added S1D3 to S1D7 to the list of SAM types recognized by the library.
- Added a new interface `ContextSetting` to manage the limitations of some not fully compliant terminals.
- Added new methods to class `LegacySamExtensionService`:
  - `ContextSetting getContextSetting()` to access to the new interface.
  - `LegacySamApiFactory getLegacySamApiFactory()` to get an implementation of the `LegacySamApiFactory` Keypop interface.
  - `CardResourceProfileExtension createLegacySamResourceProfileExtension(LegacySamSelectionExtension legacySamSelectionExtension, String powerOnDataRegex)` 
- Added project status badges on `README.md` file.
### Changed
- Refactoring:
    - Class `LegacySamCardExtensionService` -> `LegacySamExtensionService`
### Removed
- Removed methods from class `LegacySamExtensionService`:
  - `LegacySamSelectionFactory getLegacySamSelectionFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
  - `LSSecuritySettingFactory getSecuritySettingFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
  - `LSTransactionManagerFactory getTransactionManagerFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
  - `LSCommandDataFactory getCommandDataFactory()` (now provided by the `LegacySamApiFactory` Keypop interface)
### Fixed
- CI: code coverage report when releasing.
### Upgraded
- Calypsonet Terminal Reader API `1.2.0` -> Keypop Reader API `2.0.0`
- Calypsonet Terminal Card API `1.0.0` -> Keypop Card API `2.0.0`
- Calypsonet Terminal Calypso API `1.8.0` -> Keypop Calypso Card API `2.0.0`
- Calypsonet Terminal Calypso Crypto Legacy SAM API `0.2.0` -> Keypop Calypso Crypto Legacy SAM API `0.3.0`
- Keyple Service Resource Library `2.0.2` -> `3.0.0`
- Keyple Util Library `2.3.0` -> `2.3.1` (source code not impacted)

## [0.3.0] - 2023-02-27
### Upgraded
- "Calypsonet Terminal Reader API" to version `1.2.0`.
- "Calypsonet Terminal Calypso Crypto Legacy SAM API" to version `0.2.0`.
- "Google Gson Library" (com.google.code.gson) to version `2.10.1`.
 
## [0.2.0] - 2022-12-13
### Added
- `LegacySamCardExtensionService` to gather all providers.

## [0.1.0] - 2022-12-12
This is the initial release.

[unreleased]: https://github.com/eclipse/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.4.0...HEAD
[0.4.0]: https://github.com/eclipse/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/eclipse/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/eclipse/keyple-card-calypso-crypto-legacysam-java-lib/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/eclipse/keyple-card-calypso-crypto-legacysam-java-lib/releases/tag/0.1.0