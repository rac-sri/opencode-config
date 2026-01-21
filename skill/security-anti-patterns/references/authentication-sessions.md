# Authentication and Session Management

**CWE References:** CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-521 (Weak Password Requirements), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-613 (Insufficient Session Expiration)
**Severity:** Critical | **Related:** [[Authentication-Failures]]

> **Risk:** Authentication failures are a leading cause of data breaches. AI-generated code often implements weak password policies, insecure session handling, and vulnerable JWT patterns learned from outdated tutorials. Proper authentication requires defense in depth: strong credentials, secure sessions, rate limiting, and multi-factor authentication.

## 4.1 Weak Password Requirements

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No or weak password validation
// ========================================
FUNCTION register_user(username, password):
    // Vulnerable: No password strength requirements
    IF password.length < 4:
        THROW Error("Password too short")
    END IF

    // Creates accounts with passwords like "1234" or "password"
    hash = bcrypt.hash(password)
    database.insert("users", {username: username, password_hash: hash})
END FUNCTION

// ========================================
// GOOD: Strong password validation
// ========================================
FUNCTION validate_password(password):
    errors = []

    IF password.length < 12:
        errors.append("Password must be at least 12 characters")
    END IF

    IF NOT regex.match("[A-Z]", password):
        errors.append("Password must contain uppercase letter")
    END IF

    IF NOT regex.match("[a-z]", password):
        errors.append("Password must contain lowercase letter")
    END IF

    IF NOT regex.match("[0-9]", password):
        errors.append("Password must contain a number")
    END IF

    IF NOT regex.match("[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain a special character")
    END IF

    // Check against common password list
    IF is_common_password(password):
        errors.append("Password is too common")
    END IF

    RETURN errors
END FUNCTION

FUNCTION register_user(username, password):
    validation_errors = validate_password(password)
    IF validation_errors.length > 0:
        THROW ValidationError(validation_errors)
    END IF

    // Use strong hashing with appropriate cost factor
    hash = bcrypt.hash(password, rounds=12)
    database.insert("users", {username: username, password_hash: hash})
END FUNCTION
```

## 4.2 Missing Authentication on Protected Routes

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No authentication check
// ========================================
FUNCTION get_user_profile(request):
    user_id = request.get_parameter("user_id")
    // Vulnerable: Anyone can access any user's profile
    user = database.get_user(user_id)
    RETURN json_response(user)
END FUNCTION

FUNCTION update_settings(request):
    user_id = request.get_parameter("user_id")
    settings = request.get_json()
    // Vulnerable: No authentication, anyone can modify settings
    database.update("users", user_id, settings)
    RETURN success_response()
END FUNCTION

FUNCTION admin_dashboard(request):
    // Vulnerable: No admin check
    users = database.query("SELECT * FROM users")
    RETURN render_template("admin.html", {users: users})
END FUNCTION

// ========================================
// GOOD: Proper authentication and authorization
// ========================================
FUNCTION get_current_user(request):
    session_token = request.get_cookie("session_id")
    IF session_token IS NULL:
        THROW AuthenticationError("Not authenticated")
    END IF

    session = session_store.get(session_token)
    IF session IS NULL OR session.is_expired():
        THROW AuthenticationError("Session expired")
    END IF

    RETURN session.user
END FUNCTION

FUNCTION get_user_profile(request):
    // Require authentication
    current_user = get_current_user(request)

    user_id = request.get_parameter("user_id")

    // Authorization: Only allow access to own profile (or admin)
    IF user_id != current_user.id AND NOT current_user.is_admin:
        THROW AuthorizationError("Access denied")
    END IF

    user = database.get_user(user_id)
    RETURN json_response(user.public_fields())
END FUNCTION

FUNCTION update_settings(request):
    current_user = get_current_user(request)
    user_id = request.get_parameter("user_id")

    // Only allow users to update their own settings
    IF user_id != current_user.id:
        THROW AuthorizationError("Cannot modify other user's settings")
    END IF

    settings = request.get_json()
    // Validate and whitelist allowed fields
    allowed_fields = ["display_name", "email", "timezone"]
    safe_settings = filter_fields(settings, allowed_fields)

    database.update("users", user_id, safe_settings)
    RETURN success_response()
END FUNCTION

FUNCTION admin_dashboard(request):
    current_user = get_current_user(request)

    // Require admin role
    IF NOT current_user.is_admin:
        THROW AuthorizationError("Admin access required")
    END IF

    users = database.query("SELECT id, username, email FROM users")
    RETURN render_template("admin.html", {users: users})
END FUNCTION
```

## 4.3 Session Fixation

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Session ID not regenerated on login
// ========================================
FUNCTION login(request):
    username = request.get_parameter("username")
    password = request.get_parameter("password")

    user = database.find_user(username)
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        THROW AuthenticationError("Invalid credentials")
    END IF

    // Vulnerable: Using existing session ID
    // Attacker can set session ID before victim logs in
    session_id = request.get_cookie("session_id")
    IF session_id IS NULL:
        session_id = generate_session_id()
    END IF

    session_store.set(session_id, {user_id: user.id})
    response.set_cookie("session_id", session_id)
    RETURN response
END FUNCTION

// Attack scenario:
// 1. Attacker visits site, gets session_id = "abc123"
// 2. Attacker tricks victim to visit: site.com/?session_id=abc123
// 3. Victim logs in, session "abc123" now authenticated
// 4. Attacker uses session "abc123" to access victim's account

// ========================================
// GOOD: Regenerate session ID on authentication
// ========================================
FUNCTION login(request):
    username = request.get_parameter("username")
    password = request.get_parameter("password")

    user = database.find_user(username)
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        // Use constant-time comparison to prevent timing attacks
        THROW AuthenticationError("Invalid credentials")
    END IF

    // CRITICAL: Always generate new session ID on login
    old_session_id = request.get_cookie("session_id")
    IF old_session_id IS NOT NULL:
        session_store.delete(old_session_id)
    END IF

    // Create new session with secure random ID
    new_session_id = crypto.random_bytes(32).to_hex()

    session_store.set(new_session_id, {
        user_id: user.id,
        created_at: current_timestamp(),
        ip_address: request.client_ip,
        user_agent: request.user_agent
    })

    response = success_response({user: user.public_fields()})
    response.set_cookie("session_id", new_session_id, {
        httpOnly: TRUE,
        secure: TRUE,
        sameSite: "Strict",
        maxAge: 3600  // 1 hour
    })

    RETURN response
END FUNCTION

FUNCTION logout(request):
    session_id = request.get_cookie("session_id")
    IF session_id IS NOT NULL:
        session_store.delete(session_id)
    END IF

    response = redirect("/login")
    response.delete_cookie("session_id")
    RETURN response
END FUNCTION
```

## 4.4 JWT Vulnerabilities

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Insecure JWT implementation
// ========================================
CONSTANT JWT_SECRET = "secret"  // Weak secret

FUNCTION create_jwt(user_id):
    payload = {
        user_id: user_id,
        // No expiration!
    }
    // Vulnerable: Weak secret, no algorithm restriction
    RETURN jwt.encode(payload, JWT_SECRET)
END FUNCTION

FUNCTION verify_jwt(token):
    // Vulnerable: Accepts any algorithm including "none"
    payload = jwt.decode(token, JWT_SECRET)
    RETURN payload
END FUNCTION

// Attack 1: Algorithm "none" attack
// Attacker modifies token header to {"alg": "none"}
// and removes signature - token accepted without verification

// Attack 2: Algorithm confusion (RS256 -> HS256)
// If server uses RS256, attacker uses public key as HMAC secret

// ========================================
// GOOD: Secure JWT implementation
// ========================================
FUNCTION get_jwt_secret():
    secret = environment.get("JWT_SECRET")
    IF secret IS NULL OR secret.length < 32:
        THROW ConfigError("JWT_SECRET must be at least 32 characters")
    END IF
    RETURN secret
END FUNCTION

FUNCTION create_jwt(user_id):
    secret = get_jwt_secret()

    payload = {
        sub: user_id,  // Subject (standard claim)
        iat: current_timestamp(),  // Issued at
        exp: current_timestamp() + 3600,  // Expires in 1 hour
        jti: crypto.random_uuid()  // Unique token ID
    }

    // Explicitly specify algorithm
    RETURN jwt.encode(payload, secret, algorithm="HS256")
END FUNCTION

FUNCTION verify_jwt(token):
    secret = get_jwt_secret()

    TRY:
        // CRITICAL: Explicitly specify allowed algorithms
        payload = jwt.decode(token, secret, algorithms=["HS256"])

        // Verify expiration
        IF payload.exp < current_timestamp():
            THROW AuthenticationError("Token expired")
        END IF

        // Optional: Check if token was revoked
        IF is_token_revoked(payload.jti):
            THROW AuthenticationError("Token revoked")
        END IF

        RETURN payload
    CATCH JWTError:
        THROW AuthenticationError("Invalid token")
    END TRY
END FUNCTION

// For asymmetric keys (RS256), better security
FUNCTION create_jwt_asymmetric(user_id):
    private_key = load_private_key("jwt_private.pem")

    payload = {
        sub: user_id,
        iat: current_timestamp(),
        exp: current_timestamp() + 3600,
        jti: crypto.random_uuid()
    }

    RETURN jwt.encode(payload, private_key, algorithm="RS256")
END FUNCTION

FUNCTION verify_jwt_asymmetric(token):
    public_key = load_public_key("jwt_public.pem")

    TRY:
        // Only allow RS256, prevents algorithm confusion
        payload = jwt.decode(token, public_key, algorithms=["RS256"])
        RETURN payload
    CATCH JWTError:
        THROW AuthenticationError("Invalid token")
    END TRY
END FUNCTION
```

## 4.5 Missing Rate Limiting

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: No rate limiting on authentication
// ========================================
FUNCTION login(request):
    username = request.get_parameter("username")
    password = request.get_parameter("password")

    // Vulnerable: No limit on login attempts
    // Allows brute force attacks
    user = database.find_user(username)
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        THROW AuthenticationError("Invalid credentials")
    END IF

    RETURN create_session(user)
END FUNCTION

// ========================================
// GOOD: Rate limiting with account lockout
// ========================================
FUNCTION check_rate_limit(identifier, limit, window_seconds):
    key = "rate_limit:" + identifier
    current_count = cache.get(key, default=0)

    IF current_count >= limit:
        THROW RateLimitError("Too many attempts. Try again later.")
    END IF

    cache.increment(key)
    cache.set_expiry(key, window_seconds)
END FUNCTION

FUNCTION login(request):
    username = request.get_parameter("username")
    password = request.get_parameter("password")
    client_ip = request.client_ip

    // Rate limit by IP (broad protection)
    check_rate_limit("ip:" + client_ip, limit=20, window_seconds=60)

    // Rate limit by username (targeted protection)
    check_rate_limit("user:" + username, limit=5, window_seconds=300)

    user = database.find_user(username)
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        // Log failed attempt
        log_failed_login(username, client_ip)

        // Check for account lockout
        failed_attempts = get_failed_attempts(username)
        IF failed_attempts >= 5:
            lock_account(username, duration_minutes=15)
            // Don't reveal lockout to prevent enumeration
        END IF

        THROW AuthenticationError("Invalid credentials")
    END IF

    // Reset failed attempts on success
    reset_failed_attempts(username)

    RETURN create_session(user)
END FUNCTION

FUNCTION is_account_locked(username):
    lockout_until = cache.get("lockout:" + username)
    IF lockout_until IS NOT NULL AND lockout_until > current_timestamp():
        RETURN TRUE
    END IF
    RETURN FALSE
END FUNCTION

// Middleware for general rate limiting
FUNCTION rate_limit_middleware(request, next):
    client_ip = request.client_ip
    endpoint = request.path

    // Different limits for different endpoints
    limits = {
        "/api/login": {limit: 5, window: 60},
        "/api/register": {limit: 3, window: 60},
        "/api/forgot-password": {limit: 2, window: 300},
        "default": {limit: 100, window: 60}
    }

    config = limits.get(endpoint, limits["default"])

    TRY:
        check_rate_limit(client_ip + ":" + endpoint, config.limit, config.window)
        RETURN next(request)
    CATCH RateLimitError as e:
        response = error_response(429, "Too Many Requests")
        response.set_header("Retry-After", config.window)
        RETURN response
    END TRY
END FUNCTION
```

## 4.6 Insecure Password Reset

```
// PSEUDOCODE - Implement in your target language

// ========================================
// BAD: Insecure password reset implementation
// ========================================
FUNCTION request_password_reset(email):
    user = database.find_user_by_email(email)
    IF user IS NULL:
        // Vulnerable: Reveals whether email exists
        THROW Error("Email not found")
    END IF

    // Vulnerable: Predictable token
    reset_token = md5(email + current_timestamp())

    database.update("users", user.id, {reset_token: reset_token})

    // Send reset link
    send_email(email, "Reset: site.com/reset?token=" + reset_token)
END FUNCTION

FUNCTION reset_password(token, new_password):
    user = database.find_by_reset_token(token)
    IF user IS NULL:
        THROW Error("Invalid token")
    END IF

    // Vulnerable: Token never expires, can be reused
    hash = bcrypt.hash(new_password)
    database.update("users", user.id, {password_hash: hash})
END FUNCTION

// ========================================
// GOOD: Secure password reset implementation
// ========================================
FUNCTION request_password_reset(email):
    user = database.find_user_by_email(email)

    // Always return success to prevent email enumeration
    IF user IS NULL:
        // Log attempt but don't reveal to user
        log_reset_attempt(email, success=FALSE)
        RETURN success_response("If email exists, reset link sent")
    END IF

    // Generate cryptographically secure token
    reset_token = crypto.random_bytes(32).to_hex()
    token_hash = sha256(reset_token)  // Store hash, not token

    // Set expiration (15 minutes)
    expiry = current_timestamp() + 900

    database.update("users", user.id, {
        reset_token_hash: token_hash,
        reset_token_expiry: expiry
    })

    // Send reset link with original token
    send_email(email, "Reset: site.com/reset?token=" + reset_token)

    RETURN success_response("If email exists, reset link sent")
END FUNCTION

FUNCTION reset_password(token, new_password):
    // Validate new password strength
    validation_errors = validate_password(new_password)
    IF validation_errors.length > 0:
        THROW ValidationError(validation_errors)
    END IF

    // Hash the provided token to compare with stored hash
    token_hash = sha256(token)

    user = database.query(
        "SELECT * FROM users WHERE reset_token_hash = ? AND reset_token_expiry > ?",
        [token_hash, current_timestamp()]
    ).first()

    IF user IS NULL:
        THROW AuthenticationError("Invalid or expired reset token")
    END IF

    // Update password and invalidate token
    hash = bcrypt.hash(new_password, rounds=12)
    database.update("users", user.id, {
        password_hash: hash,
        reset_token_hash: NULL,
        reset_token_expiry: NULL
    })

    // Invalidate all existing sessions for this user
    invalidate_all_sessions(user.id)

    // Send confirmation email
    send_email(user.email, "Your password has been reset")

    RETURN success_response("Password reset successful")
END FUNCTION
```

## Security Headers Summary

Always set these headers for authenticated applications:

```
// Session cookie settings
Set-Cookie: session_id=abc123;
    HttpOnly;        // Prevents JavaScript access
    Secure;          // HTTPS only
    SameSite=Strict; // CSRF protection
    Path=/;
    Max-Age=3600

// Security headers
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```