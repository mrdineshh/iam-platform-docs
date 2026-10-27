package com.iamplatform.identity

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PasswordRulesTest {

    private fun settings(
        minLength: Int = 8,
        upper: Boolean = false,
        lower: Boolean = false,
        digit: Boolean = false,
        symbol: Boolean = false,
    ) = SecuritySettings(minLength, upper, lower, digit, symbol, lockoutThreshold = 0, lockoutDurationMinutes = 15, lockoutPermanent = false)

    @Test
    fun `defaults only require the minimum length`() {
        assertTrue(PasswordRules.violations("abcdefgh", settings()).isEmpty())
        assertEquals(listOf("be at least 8 characters long"), PasswordRules.violations("abc", settings()))
    }

    @Test
    fun `each character-class rule is enforced independently`() {
        assertEquals(listOf("include an uppercase letter"), PasswordRules.violations("abcdefg1!", settings(upper = true)))
        assertEquals(listOf("include a lowercase letter"), PasswordRules.violations("ABCDEFG1!", settings(lower = true)))
        assertEquals(listOf("include a number"), PasswordRules.violations("Abcdefgh!", settings(digit = true)))
        assertEquals(listOf("include a symbol"), PasswordRules.violations("Abcdefg1", settings(symbol = true)))
    }

    @Test
    fun `a password meeting every rule passes`() {
        val all = settings(minLength = 12, upper = true, lower = true, digit = true, symbol = true)
        assertTrue(PasswordRules.violations("Correct-Horse-9", all).isEmpty())
    }

    @Test
    fun `every violation is reported at once so the admin can fix them in one go`() {
        val all = settings(minLength = 12, upper = true, lower = true, digit = true, symbol = true)
        // "abc" already has a lowercase letter, so four of the five rules fail.
        assertEquals(
            listOf(
                "be at least 12 characters long",
                "include an uppercase letter",
                "include a number",
                "include a symbol",
            ),
            PasswordRules.violations("abc", all),
        )
    }

    @Test
    fun `whitespace does not count as a symbol`() {
        assertEquals(listOf("include a symbol"), PasswordRules.violations("Abcdefg 1", settings(symbol = true)))
    }

    @Test
    fun `enforce throws a WeakPasswordException with a readable message`() {
        val ex = assertThrows<WeakPasswordException> {
            PasswordRules.enforce("abc", settings(minLength = 10, digit = true))
        }
        assertEquals("Password must be at least 10 characters long, include a number.", ex.message)
    }
}
