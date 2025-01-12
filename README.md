[繁中版](./README-tw.md) | [简中版](./README-zh.md) | [العربية](./README-ar.md) | [Azərbaycan](./README-az.md) | [Български](./README-bg.md) | [বাংলা](./README-bn.md) | [Català](./README-ca.md) | [Čeština](./README-cs.md) | [Deutsch](./README-de.md) | [Ελληνικά](./README-el.md) | [Español](./README-es.md) | [فارسی](./README-fa.md) | [Français](./README-fr.md) | [हिंदी](./README-hi.md) | [Indonesia](./README-id.md) | [Italiano](./README-it.md) | [日本語](./README-ja.md) | [한국어](./README-ko.md) | [ພາສາລາວ](./README-lo.md) | [Македонски](./README-mk.md) | [മലയാളം](./README-ml.md) | [Монгол](./README-mn.md) | [Nederlands](./README-nl.md) | [Polski](./README-pl.md) | [Português (Brasil)](./README-pt_BR.md) | [Русский](./README-ru.md) | [ไทย](./README-th.md) | [Türkçe](./README-tr.md) | [Українська](./README-uk.md) | [Tiếng Việt](./README-vi.md)

# API Security Checklist

Checklist of the most important security countermeasures when designing, testing, and releasing your API.

---

## Authentication

- [ ] Don't use `Basic Auth`. Use modern authentication standards (e.g., [JWT](https://jwt.io/), [OAuth 2.0](https://oauth.net/2/), [OpenID Connect](https://openid.net/connect/)).
- [ ] Don't reinvent the wheel in `Authentication`, `token generation`, `password storage`. Use established standards and libraries.
- [ ] Use `Max Retry` with exponential backoff and account lockout policies in Login.
- [ ] Use strong encryption (AES-256 or better) for sensitive data at rest and in transit.
- [ ] Implement MFA (Multi-Factor Authentication) for enhanced security.
- [ ] Use secure session management with proper timeout and renewal mechanisms.

### JWT (JSON Web Token)

- [ ] Use a cryptographically secure random key (`JWT Secret`) with sufficient length (at least 256 bits).
- [ ] Don't extract the algorithm from the header. Force the algorithm in the backend (`HS256`, `RS256`, or `EdDSA`).
- [ ] Make token expiration (`TTL`, `RTTL`) as short as possible and implement proper token rotation.
- [ ] Don't store sensitive data in the JWT payload, it can be decoded [easily](https://jwt.io/#debugger-io).
- [ ] Avoid storing too much data. JWT is usually shared in headers and they have a size limit.
- [ ] Store token hashes in a blocklist for revoked tokens.

## Access

- [ ] Implement rate limiting with dynamic thresholds to prevent DDoS / brute-force attacks.
- [ ] Use HTTPS with TLS 1.3 and secure ciphers, disable older versions to prevent downgrade attacks.
- [ ] Use `HSTS` header with proper configuration and preload flag when possible.
- [ ] Turn off directory listings and implement proper routing.
- [ ] For private APIs, implement IP whitelisting and use mutual TLS (mTLS) when possible.
- [ ] Implement proper CORS policies with specific origins rather than wildcards.

## Authorization

### OAuth 2.0 & OpenID Connect

- [ ] Always validate `redirect_uri` server-side against a whitelist of allowed URLs.
- [ ] Prefer authorization code flow with PKCE over implicit flow.
- [ ] Use `state` parameter with a secure random value to prevent CSRF on the OAuth authorization process.
- [ ] Define and enforce scope boundaries, validate scope parameters for each application.
- [ ] Implement proper token validation and handle token revocation.
- [ ] Use short-lived access tokens and secure refresh token rotation.

## Input

- [ ] Use the proper HTTP method according to the operation: `GET (read)`, `POST (create)`, `PUT/PATCH (replace/update)`, and `DELETE (to delete a record)`, and respond with `405 Method Not Allowed` if the requested method isn't appropriate for the requested resource.
- [ ] Validate `content-type` on request Accept header (Content Negotiation) to allow only your supported format (e.g., `application/xml`, `application/json`, etc.) and respond with `406 Not Acceptable` response if not matched.
- [ ] Validate `content-type` of posted data as you accept (e.g., `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, etc.).
- [ ] Validate user input to avoid common vulnerabilities (e.g., `XSS`, `SQL-Injection`, `Remote Code Execution`, `NoSQL Injection`, etc.).
- [ ] Don't use any sensitive data (`credentials`, `Passwords`, `security tokens`, or `API keys`) in the URL, but use standard Authorization header.
- [ ] Use server-side encryption with modern algorithms (AES-256-GCM, ChaCha20-Poly1305).
- [ ] Use an API Gateway service to enable caching, Rate Limit policies (e.g., `Quota`, `Spike Arrest`, `Concurrent Rate Limit`) and deploy APIs resources dynamically.
- [ ] Implement proper input sanitization and validation for all API parameters.

## Processing

- [ ] Verify all endpoints are protected by appropriate authentication and authorization mechanisms.
- [ ] Use resource-based URLs. Prefer `/me/orders` instead of `/user/654321/orders`.
- [ ] Use UUIDs or other non-sequential identifiers to prevent enumeration attacks.
- [ ] For XML processing, disable entity parsing to prevent `XXE` (XML external entity attack).
- [ ] For parsers (XML, YAML, JSON, etc.), disable entity expansion to prevent `Billion Laughs/XML bomb` attacks.
- [ ] Use cloud storage services or CDNs for file uploads with proper access controls.
- [ ] For heavy operations, use async processing with Workers and Message Queues.
- [ ] Ensure DEBUG mode is disabled in production.
- [ ] Enable security headers and use secure configurations.
- [ ] Implement proper error handling without exposing sensitive details.

## Output

- [ ] Send `X-Content-Type-Options: nosniff` header.
- [ ] Send `X-Frame-Options: deny` header.
- [ ] Send `Content-Security-Policy` header with strict policies.
- [ ] Remove fingerprinting headers - `X-Powered-By`, `Server`, `X-AspNet-Version`, etc.
- [ ] Force `content-type` for your response with proper charset.
- [ ] Don't return sensitive data like `credentials`, `passwords`, or `security tokens`.
- [ ] Return the proper status code according to the operation completed. (e.g., `200 OK`, `400 Bad Request`, `401 Unauthorized`, `405 Method Not Allowed`, etc.).
- [ ] Implement proper JSON serialization with security in mind.

## CI & CD

- [ ] Implement comprehensive unit/integration tests with high coverage.
- [ ] Use automated code review tools and security scanners.
- [ ] Ensure all components are scanned for vulnerabilities before deployment.
- [ ] Run automated security tests (SAST/DAST) in your pipeline.
- [ ] Use dependency scanning and keep dependencies updated.
- [ ] Implement blue-green deployments or canary releases.
- [ ] Use infrastructure as code with security policies.
- [ ] Implement proper secrets management.

## Monitoring

- [ ] Implement centralized logging with proper log levels and encryption.
- [ ] Use APM (Application Performance Monitoring) tools for traffic analysis.
- [ ] Configure alerts for suspicious activities across multiple channels.
- [ ] Ensure compliance with data privacy regulations in logging.
- [ ] Use SIEM systems for security monitoring and threat detection.
- [ ] Implement proper audit logging for security events.
- [ ] Use real-time monitoring and alerting for critical security events.

---

## See also:

- [yosriady/api-development-tools](https://github.com/yosriady/api-development-tools) - A collection of useful resources for building RESTful HTTP+JSON APIs.

---

# Contribution

Feel free to contribute by forking this repository, making some changes, and submitting pull requests. For any questions drop us an email at `team@shieldfy.io`.
