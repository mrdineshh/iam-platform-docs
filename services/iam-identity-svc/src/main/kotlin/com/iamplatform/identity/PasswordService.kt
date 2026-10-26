package com.iamplatform.identity

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.stereotype.Component

@Component
class PasswordService(
    private val pepperProvider: PasswordPepperProvider,
) {
    // Params confirmed with the product owner during the Module 1 interview
    // (2026-08-03, docs/DECISIONS.md): Argon2id, m=19456 KiB, t=2, p=1,
    // OWASP baseline. saltLength/hashLength are Argon2PasswordEncoder's own
    // generation parameters, not part of that decision.
    private val encoder = Argon2PasswordEncoder(16, 32, 1, 19456, 2)

    // encoder.encode() is a platform type from a Spring @Nullable-annotated
    // Java interface; -Xjsr305=strict makes Kotlin see it as String?, but it
    // never actually returns null.
    fun hash(rawPassword: String): String = encoder.encode(rawPassword + pepperProvider.get())!!

    fun matches(rawPassword: String, hash: String): Boolean = encoder.matches(rawPassword + pepperProvider.get(), hash)
}
