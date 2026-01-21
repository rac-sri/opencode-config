# Security Anti-Patterns for AI Code Generation

This skill provides a comprehensive reference for security vulnerabilities that commonly appear in AI-generated code, with secure alternatives and implementation examples.

## Overview

AI-generated code has significantly higher rates of security vulnerabilities compared to human-written code:
- **86% XSS failure rate** in AI code vs 31.6% in human code
- **2.74x more likely** to contain XSS vulnerabilities
- **5-21% hallucination rate** for package names
- **21.7% of suggested packages don't exist**

This skill documents the most critical anti-patterns with pseudocode examples that can be implemented in any programming language.

## Quick Start

1. **Review the patterns** in `references/` before generating code
2. **Include anti-patterns** in your AI system prompts
3. **Reference secure examples** when implementing features
4. **Use as checklist** during code review

## Coverage Areas

### 🔐 Secrets & Credentials
- Hardcoded API keys and passwords
- Credentials in config files and client code
- Insecure storage and rotation patterns

### 💉 Injection Attacks
- SQL, Command, LDAP, XPath, NoSQL injection
- Template injection (SSTI)
- Parameterized query alternatives

### 🕷️ Cross-Site Scripting (XSS)
- Reflected, Stored, and DOM-based XSS
- Content Security Policy implementation
- Context-specific output encoding

### 🔒 Authentication & Sessions
- Weak password policies
- Missing authentication checks
- Session fixation and JWT vulnerabilities

## Usage Examples

### In System Prompts

```
IMPORTANT: Avoid these security anti-patterns when generating code:

1. Never hardcode credentials, API keys, or secrets
2. Always use parameterized queries for database operations
3. HTML-encode all user input before rendering in web pages
4. Validate and sanitize all user inputs
5. Use cryptographically secure random for security tokens
6. Implement proper authentication and session management

For secure implementations, reference the GOOD examples in the security-anti-patterns skill.
```

### During Code Review

Use this skill as a checklist when reviewing AI-generated code:

- [ ] No hardcoded secrets or credentials
- [ ] All database queries use parameterized statements
- [ ] User input is properly encoded for output context
- [ ] Authentication is implemented and enforced
- [ ] Sessions are securely managed
- [ ] Random values use cryptographically secure sources

## File Structure

```
skill/security-anti-patterns/
├── SKILL.md                    # Skill definition and overview
├── README.md                   # This file
└── references/
    ├── secrets-credentials.md  # Credential management patterns
    ├── injection-vulnerabilities.md  # Injection attack prevention
    ├── cross-site-scripting.md  # XSS prevention and encoding
    └── authentication-sessions.md    # Auth and session security
```

## Implementation Notes

### Pseudocode Adaptation

All examples use pseudocode that should be adapted to your target language:

```pseudocode
FUNCTION example_function(param):
    // Implementation here
    RETURN result
END FUNCTION
```

**JavaScript/TypeScript:**
```javascript
function exampleFunction(param) {
    // Implementation here
    return result;
}
```

**Python:**
```python
def example_function(param):
    # Implementation here
    return result
```

### Context-Specific Encoding

Different output contexts require different encoding:

- **HTML Content**: HTML entity encoding (`&lt;` for `<`)
- **HTML Attributes**: Quote and HTML-encode values
- **JavaScript**: JSON encoding or proper escaping
- **CSS**: Validate allowed values, avoid user input
- **URL**: URL encoding for parameters

## Common Mistakes to Avoid

1. **String Concatenation in SQL**: Leads to injection attacks
2. **Direct innerHTML Assignment**: Causes XSS vulnerabilities
3. **Plaintext Password Storage**: Use bcrypt/argon2 with salt
4. **Client-Side Secrets**: Never expose keys in frontend code
5. **Weak Random Generation**: Use crypto.randomBytes() equivalent

## Related Skills

- `sharp-edges` - General anti-patterns and error-prone APIs
- `senior-security` - Security architecture and penetration testing
- `constant-time-analysis` - Timing attack prevention
- `variant-analysis` - Finding similar vulnerabilities across codebases
- `rust-security` - Rust-specific security best practices

## Contributing

When adding new anti-patterns:

1. Follow the BAD/GOOD structure
2. Include pseudocode examples
3. Reference CWE numbers when applicable
4. Provide severity ratings
5. Include real-world attack scenarios

## License

This security anti-patterns guide is based on industry best practices and vulnerability research from sources including OWASP, CWE, and academic studies on AI-generated code security.