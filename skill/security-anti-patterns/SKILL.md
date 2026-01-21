---
name: security-anti-patterns
description: "Comprehensive security anti-patterns guide for AI-generated code, covering critical vulnerabilities like XSS, injection, and authentication failures with secure alternatives. Use when reviewing AI-generated code, implementing security patterns, or as context for AI code generation. Triggers: XSS, SQL injection, hardcoded credentials, authentication bypass, session fixation, JWT vulnerabilities, SSTI, command injection."
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Security Anti-Patterns for AI Code Generation

Complete guide to avoiding security vulnerabilities in AI-generated code, based on breadth-first coverage of common attack vectors.

## Purpose

This skill provides a comprehensive reference for security anti-patterns that frequently appear in AI-generated code. Each section shows vulnerable patterns (BAD) and secure alternatives (GOOD), with pseudocode examples that can be implemented in any programming language.

## Key Statistics

- **AI-generated code has 86% XSS failure rate** (vs 31.6% human code)
- **AI code is 2.74x more likely** to contain XSS vulnerabilities
- **5-21% of AI-suggested packages don't exist** (slopsquatting risk)
- **21.7% hallucination rate** for package names

## Coverage Areas

### 1. Secrets and Credentials Management
- Hardcoded passwords and API keys
- Credentials in configuration files
- Secrets in client-side code
- Insecure credential storage
- Missing secret rotation

### 2. Injection Vulnerabilities
- SQL injection (string concatenation)
- Command injection (shell commands)
- LDAP injection
- XPath injection
- NoSQL injection
- Template injection (SSTI)

### 3. Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Missing Content-Security-Policy
- Improper output encoding (context-specific)

### 4. Authentication and Session Management
- Weak password requirements
- Missing authentication checks
- Insecure session handling
- Session fixation vulnerabilities
- JWT misuse patterns

## Reference Documentation

All anti-patterns are documented in the `references/` directory with detailed explanations and examples:

- `secrets-credentials.md` - Credential management anti-patterns
- `injection-vulnerabilities.md` - All injection attack vectors
- `cross-site-scripting.md` - XSS prevention and encoding
- `authentication-sessions.md` - Auth and session security patterns

## Usage in AI Code Generation

Include references to this skill in your system prompts:

```
When generating code, avoid these anti-patterns:
- Never hardcode credentials or secrets
- Always use parameterized queries for databases
- HTML-encode all user input before rendering
- Validate and sanitize all inputs
- Use cryptographically secure random for security tokens

Reference the secure patterns in security-anti-patterns skill for correct implementations.
```

## Implementation Languages

Examples are provided in pseudocode that can be adapted to:
- JavaScript/TypeScript
- Python
- Java
- C#
- Go
- PHP
- Ruby
- And other languages

## Integration with Other Skills

This skill complements:
- `sharp-edges` - General anti-patterns and error-prone APIs
- `senior-security` - Security architecture and penetration testing
- `constant-time-analysis` - Timing attack prevention
- `variant-analysis` - Finding similar vulnerabilities