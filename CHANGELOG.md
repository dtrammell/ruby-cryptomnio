# Changelog

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
