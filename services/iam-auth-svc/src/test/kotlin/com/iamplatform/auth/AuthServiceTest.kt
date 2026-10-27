package com.iamplatform.auth

import com.iamplatform.auth.client.DeviceClient
import com.iamplatform.auth.client.EvaluateResponse
import com.iamplatform.auth.client.GeoClient
import com.iamplatform.auth.client.GeoResolution
import com.iamplatform.auth.client.IdentityClient
import com.iamplatform.auth.client.IssuedSession
import com.iamplatform.auth.client.PolicyClient
import com.iamplatform.auth.client.PushSendResult
import com.iamplatform.auth.client.RemoteDeviceStatus
import com.iamplatform.auth.client.RemotePushResult
import com.iamplatform.auth.client.RemoteUserRole
import com.iamplatform.auth.client.RemoteUserStatus
import com.iamplatform.auth.client.SessionClient
import com.iamplatform.auth.client.TotpVerifyResult
import com.iamplatform.auth.client.VerifyPasswordResponse
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import io.github.resilience4j.circuitbreaker.CallNotPermittedException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals

class AuthServiceTest {

    private val identityClient = mock<IdentityClient>()
    private val geoClient = mock<GeoClient>()
    private val policyClient = mock<PolicyClient>()
    private val deviceClient = mock<DeviceClient>()
    private val sessionClient = mock<SessionClient>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = AuthService(identityClient, geoClient, policyClient, deviceClient, sessionClient, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val request = LoginRequest(tenantId, "alice@acme.com", "correct-password", "8.8.8.8")

    @Test
    fun `successful login (push approved) issues a session and publishes auth-login_success`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId))
            .thenReturn(PushSendResult(UUID.randomUUID(), RemotePushResult.APPROVED))
        val expiresAt = Instant.now()
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any()))
            .thenReturn(IssuedSession("tok-123", UUID.randomUUID(), expiresAt))

        val result = service.login(request)

        assertEquals("tok-123", result.token)
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("auth.login_success", captor.firstValue.action)
        assertEquals(AuditResult.SUCCESS, captor.firstValue.result)
        assertEquals("US", captor.firstValue.geo)
    }

    @Test
    fun `wrong password returns 401-mapped exception and publishes auth-login_failure, calling nothing else`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = false))

        assertThrows<InvalidCredentialsException> { service.login(request) }

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("auth.login_failure", captor.firstValue.action)
        assertEquals(AuditResult.FAILURE, captor.firstValue.result)
        verify(geoClient, never()).resolve(any())
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `suspended account is denied without calling geo, policy, or session`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.SUSPENDED))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }
        assertEquals("account suspended", ex.message)
        assertEquals(AuthErrorCode.ACCOUNT_SUSPENDED, ex.errorCode)

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals(AuditResult.DENIED, captor.firstValue.result)
        verify(geoClient, never()).resolve(any())
        verify(policyClient, never()).evaluate(any(), any(), anyOrNull(), any(), anyOrNull())
    }

    @Test
    fun `unresolved location is denied, never an automatic pass, without calling policy`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = false))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }
        assertEquals("location could not be verified", ex.message)
        verify(policyClient, never()).evaluate(any(), any(), anyOrNull(), any(), anyOrNull())
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `geo-svc unreachable is denied, never an automatic pass`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenThrow(
            CallNotPermittedException.createCallNotPermittedException(
                io.github.resilience4j.circuitbreaker.CircuitBreaker.ofDefaults("geo-svc"),
            ),
        )

        val ex = assertThrows<LoginDeniedException> { service.login(request) }
        assertEquals("location could not be verified", ex.message)
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `policy denial is surfaced with its reason and scope, without calling session`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "KP"))
        whenever(policyClient.evaluate(tenantId, userId, null, "KP", "8.8.8.8"))
            .thenReturn(EvaluateResponse(allowed = false, reason = "country 'KP' is in blockedCountries", policyScopeApplied = "TENANT"))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }
        assertEquals("country 'KP' is in blockedCountries", ex.message)

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("TENANT", captor.firstValue.policyScopeApplied)
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `policy-svc unreachable is denied, never an automatic pass`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8"))
            .thenThrow(CallNotPermittedException.createCallNotPermittedException(
                io.github.resilience4j.circuitbreaker.CircuitBreaker.ofDefaults("policy-svc"),
            ))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }
        assertEquals("policy could not be evaluated", ex.message)
    }

    @Test
    fun `session issuance failure propagates uncaught and does not publish a success event`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId))
            .thenReturn(PushSendResult(UUID.randomUUID(), RemotePushResult.APPROVED))
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any()))
            .thenThrow(CallNotPermittedException.createCallNotPermittedException(
                io.github.resilience4j.circuitbreaker.CircuitBreaker.ofDefaults("session-svc"),
            ))

        assertThrows<CallNotPermittedException> { service.login(request) }
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `totpCode present uses the TOTP path, not push, and proceeds on a valid code`() {
        val totpRequest = LoginRequest(tenantId, "alice@acme.com", "correct-password", "8.8.8.8", totpCode = "123456")
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.verifyTotp(tenantId, userId, "123456"))
            .thenReturn(TotpVerifyResult(valid = true, status = RemoteDeviceStatus.ACTIVE))
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any()))
            .thenReturn(IssuedSession("tok-456", UUID.randomUUID(), Instant.now()))

        val result = service.login(totpRequest)

        assertEquals("tok-456", result.token)
        verify(deviceClient, never()).sendPush(any(), any())
    }

    @Test
    fun `login response carries the identity-svc role, defaulting to USER when absent`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE, role = RemoteUserRole.ADMIN))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId)).thenReturn(PushSendResult(UUID.randomUUID(), RemotePushResult.APPROVED))
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any()))
            .thenReturn(IssuedSession("tok-role", UUID.randomUUID(), Instant.now()))

        val result = service.login(request)

        assertEquals("ADMIN", result.role)
    }

    @Test
    fun `wrong TOTP code is denied without issuing a session`() {
        val totpRequest = LoginRequest(tenantId, "alice@acme.com", "correct-password", "8.8.8.8", totpCode = "000000")
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.verifyTotp(tenantId, userId, "000000"))
            .thenReturn(TotpVerifyResult(valid = false, status = RemoteDeviceStatus.PENDING))

        val ex = assertThrows<LoginDeniedException> { service.login(totpRequest) }

        assertEquals("invalid second factor code", ex.message)
        assertEquals(AuthErrorCode.TOTP_INVALID, ex.errorCode)
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `locked device is denied with a specific reason, distinct from a wrong code`() {
        val totpRequest = LoginRequest(tenantId, "alice@acme.com", "correct-password", "8.8.8.8", totpCode = "000000")
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.verifyTotp(tenantId, userId, "000000"))
            .thenReturn(TotpVerifyResult(valid = false, status = RemoteDeviceStatus.LOCKED))

        val ex = assertThrows<LoginDeniedException> { service.login(totpRequest) }

        assertEquals("second factor locked", ex.message)
    }

    @Test
    fun `push denied is surfaced as a login denial without issuing a session`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId))
            .thenReturn(PushSendResult(UUID.randomUUID(), RemotePushResult.DENIED))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }

        assertEquals("second factor denied", ex.message)
        assertEquals(AuthErrorCode.PUSH_DENIED, ex.errorCode)
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `push timeout is denied, never an automatic pass`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId))
            .thenReturn(PushSendResult(UUID.randomUUID(), RemotePushResult.TIMEOUT))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }

        assertEquals("second factor timed out", ex.message)
    }

    @Test
    fun `device-svc unreachable during push is denied, never an automatic pass`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId)).thenThrow(
            CallNotPermittedException.createCallNotPermittedException(
                io.github.resilience4j.circuitbreaker.CircuitBreaker.ofDefaults("device-svc"),
            ),
        )

        val ex = assertThrows<LoginDeniedException> { service.login(request) }

        assertEquals("second factor unavailable", ex.message)
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `no device enrolled (404 from device-svc) is denied with a specific reason`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId)).thenThrow(
            org.springframework.web.client.HttpClientErrorException.create(
                org.springframework.http.HttpStatus.NOT_FOUND, "Not Found", org.springframework.http.HttpHeaders.EMPTY, ByteArray(0), null,
            ),
        )

        val ex = assertThrows<LoginDeniedException> { service.login(request) }

        assertEquals("no push-capable second factor enrolled", ex.message)
    }

    @Test
    fun `logout terminates the session with a logout reason`() {
        service.logout("some-token")

        verify(sessionClient).terminate("some-token", "logout")
    }

    @Test
    fun `a locked account is denied with ACCOUNT_LOCKED, audited, and nothing else is called`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = false, locked = true))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }

        assertEquals(AuthErrorCode.ACCOUNT_LOCKED, ex.errorCode)
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("auth.login_denied", captor.firstValue.action)
        assertEquals(AuditResult.DENIED, captor.firstValue.result)
        verify(geoClient, never()).resolve(any())
        verify(sessionClient, never()).issue(any(), any(), any(), any())
    }

    @Test
    fun `precheck also reports a locked account as ACCOUNT_LOCKED`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = false, locked = true, permanentlyLocked = true))

        val ex = assertThrows<LoginDeniedException> {
            service.precheck(PrecheckRequest(tenantId, "alice@acme.com", "correct-password", "8.8.8.8"))
        }

        assertEquals(AuthErrorCode.ACCOUNT_LOCKED, ex.errorCode)
        verify(geoClient, never()).resolve(any())
    }
}
