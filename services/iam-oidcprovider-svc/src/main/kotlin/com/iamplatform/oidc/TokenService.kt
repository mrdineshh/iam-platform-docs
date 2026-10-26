package com.iamplatform.oidc

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.stereotype.Component
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.UUID

class InvalidTokenException(message: String) : RuntimeException(message)

@Component
class TokenService(
    private val signingKeyProvider: OidcSigningKeyProvider,
) {

    fun issueIdToken(issuer: String, clientId: UUID, subject: UUID, tenantId: UUID, email: String, ttl: Duration): String {
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(subject.toString())
            .audience(clientId.toString())
            .claim("tenant_id", tenantId.toString())
            .claim("email", email)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plus(ttl)))
            .build()
        return sign(claims)
    }

    fun issueAccessToken(issuer: String, subject: UUID, tenantId: UUID, email: String, scope: String, ttl: Duration): String {
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(subject.toString())
            .claim("tenant_id", tenantId.toString())
            .claim("email", email)
            .claim("scope", scope)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plus(ttl)))
            .build()
        return sign(claims)
    }

    /** Throws InvalidTokenException for a bad signature, malformed token, or expiry -- never returns a partial result. */
    fun verifyAndParse(token: String): JWTClaimsSet {
        val signedJwt = try {
            SignedJWT.parse(token)
        } catch (ex: Exception) {
            throw InvalidTokenException("malformed token")
        }

        val verifier = RSASSAVerifier(signingKeyProvider.get().toRSAPublicKey())
        if (!signedJwt.verify(verifier)) {
            throw InvalidTokenException("signature verification failed")
        }

        val claims = signedJwt.jwtClaimsSet
        val expiry = claims.expirationTime ?: throw InvalidTokenException("no expiry claim")
        if (expiry.before(Date.from(Instant.now()))) {
            throw InvalidTokenException("token expired")
        }
        return claims
    }

    fun publicJwkSet(): JWKSet = JWKSet(signingKeyProvider.get().toPublicJWK())

    private fun sign(claims: JWTClaimsSet): String {
        val rsaKey = signingKeyProvider.get()
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.keyID).build()
        val signedJwt = SignedJWT(header, claims)
        try {
            signedJwt.sign(RSASSASigner(rsaKey))
        } catch (ex: JOSEException) {
            throw IllegalStateException("failed to sign token", ex)
        }
        return signedJwt.serialize()
    }
}
