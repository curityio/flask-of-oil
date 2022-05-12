## Flask-of-oil changelog

## Unreleased

Feature:
    - Refresh JWKS from JWKS URI when no suitable keys found in current JWKS.

Fix:
    - Fixed verification of `aud` claim. Now properly verifies audience where a token contains an array of audiences.

## 1.1.0 (2021-05-05)

Feature:
    - Allow configuring multiple issuers.

Fix:
    - Return default errors in all cases so that they can be properly caught by flask error handlers.
    - You can now omit passing required claims.

## 1.0.1 (2020-02-21)

Initial release.
