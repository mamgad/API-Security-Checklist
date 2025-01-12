[繁中版](./README-tw.md) | [简中版](./README-zh.md) | [العربية](./README-ar.md) | [Azərbaycan](./README-az.md) | [Български](./README-bg.md) | [বাংলা](./README-bn.md) | [Català](./README-ca.md) | [Čeština](./README-cs.md) | [Deutsch](./README-de.md) | [Ελληνικά](./README-el.md) | [Español](./README-es.md) | [فارسی](./README-fa.md) | [Français](./README-fr.md) | [हिंदी](./README-hi.md) | [Indonesia](./README-id.md) | [Italiano](./README-it.md) | [日本語](./README-ja.md) | [한국어](./README-ko.md) | [ພາສາລາວ](./README-lo.md) | [Македонски](./README-mk.md) | [മലയാളം](./README-ml.md) | [Монгол](./README-mn.md) | [Nederlands](./README-nl.md) | [Polski](./README-pl.md) | [Português (Brasil)](./README-pt_BR.md) | [Русский](./README-ru.md) | [ไทย](./README-th.md) | [Türkçe](./README-tr.md) | [Українська](./README-uk.md) | [Tiếng Việt](./README-vi.md)

# API Security Checklist

A comprehensive checklist for implementing security best practices in modern API development. This checklist helps you build and maintain secure APIs by following industry standards and best practices.

---

## Table of Contents

- [Authentication](#authentication)
- [Access Control](#access-control)
- [Input Validation & Processing](#input-validation--processing)
- [Output Security](#output-security)
- [Infrastructure Security](#infrastructure-security)
- [Modern Security Considerations](#modern-security-considerations)
- [DevSecOps](#devsecops)
- [Monitoring & Response](#monitoring--response)
- [Contributing](#contributing)

## Authentication

### Core Authentication
- [ ] Don't use `Basic Auth`. Use modern authentication standards (OAuth 2.1+, [JWT](https://jwt.io/), [PASETO](https://paseto.io/)).
- [ ] Support passwordless authentication (WebAuthn, FIDO2) where applicable.
- [ ] Enforce Multi-Factor Authentication (MFA) for sensitive operations.
- [ ] Use secure password hashing (Argon2id, bcrypt) with appropriate work factors.
- [ ] Implement automated key rotation and secure key management.
- [ ] Use environment-specific API keys with proper scope limitations.
- [ ] Enable rate limiting with exponential backoff on authentication endpoints.
- [ ] Configure secure session management with proper timeout and renewal.

### JWT Security
- [ ] Use cryptographically secure algorithms (EdDSA, ES256, RS256).
- [ ] Implement JWK rotation and proper key management.
- [ ] Use encrypted JWTs (JWE) for sensitive payload data.
- [ ] Make token expiration (`TTL`) as short as possible.
- [ ] Implement proper token validation and revocation.
- [ ] Don't store sensitive data in JWT payload.
- [ ] Store token hashes in a blocklist for revoked tokens.

## Access Control

### Authentication & Authorization
- [ ] Implement Role-Based Access Control (RBAC) with principle of least privilege.
- [ ] Use Attribute-Based Access Control (ABAC) for complex permissions.
- [ ] Validate `redirect_uri` server-side against a whitelist.
- [ ] Implement proper scope validation for OAuth 2.0/OpenID Connect.
- [ ] Use resource-based URLs (e.g., `/me/orders` instead of `/user/654321/orders`).
- [ ] For private APIs, implement IP whitelisting and mutual TLS (mTLS).

### Network Security
- [ ] Use HTTPS with TLS 1.3, disable older versions.
- [ ] Enable `HSTS` header with proper configuration and preload.
- [ ] Implement proper CORS policies with specific origins.
- [ ] Deploy Web Application Firewall (WAF) rules.
- [ ] Use API gateway for rate limiting and security controls.

## Input Validation & Processing

### Request Security
- [ ] Validate `content-type` headers strictly.
- [ ] Sanitize and validate all input parameters.
- [ ] Use parameterized queries to prevent injection attacks.
- [ ] Protect against common vulnerabilities (XSS, SQL Injection, NoSQL Injection, XXE).
- [ ] Implement proper file upload validation and scanning.
- [ ] Use appropriate HTTP methods and return proper status codes.
- [ ] Never expose sensitive data in URLs.

### Processing Security
- [ ] Disable entity parsing in XML/YAML to prevent XXE attacks.
- [ ] Prevent Billion Laughs/XML bomb attacks in parsers.
- [ ] Use cloud storage with proper access controls for uploads.
- [ ] Implement async processing for heavy operations.
- [ ] Ensure DEBUG mode is disabled in production.
- [ ] Handle errors without exposing sensitive details.

## Output Security

### Response Headers
- [ ] Set `X-Content-Type-Options: nosniff`
- [ ] Set `X-Frame-Options: deny`
- [ ] Configure strict Content Security Policy (CSP)
- [ ] Remove fingerprinting headers
- [ ] Set proper CORS headers
- [ ] Implement proper caching headers

### Response Content
- [ ] Force `content-type` with proper charset
- [ ] Never return sensitive data
- [ ] Use proper HTTP status codes
- [ ] Implement secure JSON serialization
- [ ] Validate and sanitize all output

## Infrastructure Security

### Core Infrastructure
- [ ] Implement comprehensive container security
- [ ] Use secrets management solutions
- [ ] Enable infrastructure as code security
- [ ] Configure proper backup and recovery
- [ ] Implement network segmentation
- [ ] Use secure service mesh
- [ ] Enable cloud security controls
- [ ] Protect edge computing endpoints

## Modern Security Considerations

### Modern Architectures
- [ ] Secure GraphQL implementations
- [ ] Protect WebSocket connections
- [ ] Secure gRPC services
- [ ] Implement serverless security
- [ ] Configure Kubernetes security
- [ ] Enable zero-trust architecture
- [ ] Protect microservices communication
- [ ] Secure API gateway integration

## DevSecOps

### Security Pipeline
- [ ] Run automated security tests (SAST/DAST)
- [ ] Implement dependency scanning
- [ ] Enable container scanning
- [ ] Use automated code review
- [ ] Implement secure CI/CD
- [ ] Enable infrastructure scanning
- [ ] Use blue-green deployments
- [ ] Implement proper secrets rotation

## Monitoring & Response

### Security Monitoring
- [ ] Implement centralized logging with encryption
- [ ] Use APM tools for traffic analysis
- [ ] Enable real-time security alerts
- [ ] Implement audit logging
- [ ] Use SIEM for threat detection
- [ ] Enable anomaly detection
- [ ] Configure compliance monitoring
- [ ] Implement incident response

---

## See also:

- [yosriady/api-development-tools](https://github.com/yosriady/api-development-tools) - A collection of useful resources for building RESTful HTTP+JSON APIs.

## Contributing

Feel free to contribute by forking this repository, making changes, and submitting pull requests. For questions or suggestions, please open an issue or contact us at `team@shieldfy.io`.
