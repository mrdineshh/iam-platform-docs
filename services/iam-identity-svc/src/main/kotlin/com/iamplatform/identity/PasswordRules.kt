package com.iamplatform.identity

/** Thrown when a new password doesn't meet the tenant's rules. The message is safe to show the admin who typed it. */
class WeakPasswordException(val violations: List<String>) :
    RuntimeException("Password must " + violations.joinToString(", ") + ".")

/**
 * Pure function over a tenant's rules (FR-3.1): no I/O, so it is exhaustively
 * unit-testable. Only complexity is checked here; breached-password screening
 * (FR-3.4), history (FR-3.2) and expiry (FR-3.3) are separate, unbuilt items.
 */
object PasswordRules {

    fun violations(password: String, settings: SecuritySettings): List<String> {
        val problems = mutableListOf<String>()
        if (password.length < settings.passwordMinLength) {
            problems += "be at least ${settings.passwordMinLength} characters long"
        }
        if (settings.passwordRequireUppercase && password.none { it.isUpperCase() }) {
            problems += "include an uppercase letter"
        }
        if (settings.passwordRequireLowercase && password.none { it.isLowerCase() }) {
            problems += "include a lowercase letter"
        }
        if (settings.passwordRequireDigit && password.none { it.isDigit() }) {
            problems += "include a number"
        }
        if (settings.passwordRequireSymbol && password.none { !it.isLetterOrDigit() && !it.isWhitespace() }) {
            problems += "include a symbol"
        }
        return problems
    }

    fun enforce(password: String, settings: SecuritySettings) {
        val problems = violations(password, settings)
        if (problems.isNotEmpty()) throw WeakPasswordException(problems)
    }
}
