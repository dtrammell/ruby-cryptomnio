# Changelog

## 0.2.2 - 2026-10-02

### Fixed

*   Replaced global `$balance` with a local variable in `get_account_balance_symbol` and `get_account_available_balance_symbol` to prevent state leakage between calls (Issue #5).
*   Made currency symbol matching case-insensitive and nil-safe in `get_account_balance_symbol` and `get_account_available_balance_symbol` (Issue #17).
*   Single-sourced gem `VERSION` and `DATE` from `lib/cryptomnio/version.rb` to prevent version/date drift between the gemspec, runtime, and packaged artifact (Issue #18).
*   Corrected `geminfo` to print the Cryptomnio API version (`API_VERSION`) on the "Cryptomnio API Version:" line instead of the gem version (Issue #19).

### Changed

*   Updated `cryptomnio.gemspec` `homepage` to point at the GitHub repository: `https://github.com/dtrammell/ruby-cryptomnio` (Issue #18).
*   Added MIT `LICENSE` file at the repository root (Issue #18).

## 0.2.0 - 2026-05-26

### Added

*   Explicit `require 'openssl'` for cryptographic operations (Issue #7).
*   Runtime dependency on `rest-client (~> 2.1)` in `cryptomnio.gemspec` (Issue #8).

### Changed

*   Improved query string formatting in `get_market_orderbook`, `get_market_orderbook_depth_price`, `get_market_orderbook_depth_volume`, and `get_market_trades` methods from string concatenation to array joining for better readability and maintainability (Issue #6).

### Fixed

*   Resolved issues with query string parameter handling for improved API request reliability (Issue #6).
*   Ensured OpenSSL is explicitly loaded to prevent potential cryptographic errors (Issue #7).
*   Corrected `rest-client` dependency specification in `cryptomnio.gemspec` (Issue #8).
