## Flask-of-oil changelog

## Unreleased

## 1.2.1 (2023-05-29)

Feature:
    - Updated flask to version 2.3.2.

Fix:
    - Properly set empty scope in JWT payload, if no scope present in the JWT.

## 1.2.0 (2022-05-12)

Feature:
    - Refresh JWKS from JWKS URI when no suitable keys found in current JWKS.

Fix:
    - Fixed verification of `aud` claim. Now properly verifies audience where a token contains a single audience value.

## 1.1.0 (2021-05-05)

Feature:
    - Allow configuring multiple issuers.

Fix:
    - Return default errors in all cases so that they can be properly caught by flask error handlers.
    - You can now omit passing required claims.

## 1.0.1 (2020-02-21)

Initial release.
