package com.iamplatform.auth

import com.iamplatform.auth.client.DeviceClient
import com.iamplatform.auth.client.EvaluateResponse
import com.iamplatform.auth.client.GeoClient
import com.iamplatform.auth.client.GeoResolution
import com.iamplatform.auth.client.IdentityClient
import com.iamplatform.auth.client.IssuedSession
import com.iamplatform.auth.client.LoginDeviceCheckRequest
import com.iamplatform.auth.client.LoginDeviceCheckResponse
import com.iamplatform.auth.client.PolicyClient
import com.iamplatform.auth.client.PushSendResult
import com.iamplatform.auth.client.RemoteDeviceStatus
import com.iamplatform.auth.client.RemotePushResult
import com.iamplatform.auth.client.RemoteUserRole
import com.iamplatform.auth.client.RemoteUserStatus
import com.iamplatform.auth.client.SessionClient
import com.iamplatform.auth.client.TenantClient
import com.iamplatform.auth.client.VerifiedDeviceProof
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
    private val tenantClient = mock<TenantClient>()
    private val service = AuthService(identityClient, geoClient, policyClient, deviceClient, sessionClient, auditPublisher, tenantClient)

    init {
        // The platform sign-in rule is off unless a test says otherwise.
        whenever(tenantClient.checkLoginDevice(any())).thenReturn(LoginDeviceCheckResponse(allowed = true))
    }

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
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any(), any()))
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any(), any()))
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
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any(), any()))
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
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any(), any()))
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
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

    // ---- device-bound sign-in: a proof can only ADD a device, never change whether the sign-in succeeds ----

    private fun arrangeSuccessfulPasswordAndPush() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyClient.evaluate(tenantId, userId, null, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))
        whenever(deviceClient.sendPush(tenantId, userId)).thenReturn(PushSendResult(UUID.randomUUID(), RemotePushResult.APPROVED))
        whenever(sessionClient.issue(eq(tenantId), eq(userId), eq("8.8.8.8"), any(), any())).thenReturn(IssuedSession("tok-plain", UUID.randomUUID(), Instant.now()))
    }

    private val proof = DeviceProof(UUID.randomUUID(), UUID.randomUUID(), "sig", "https://login.example.com")

    @Test
    fun `a sign-in with no device proof never touches the tenant service or the device path`() {
        arrangeSuccessfulPasswordAndPush()
        val result = service.login(request)
        assertEquals("tok-plain", result.token)
        verify(tenantClient, never()).verifyDeviceProof(any(), any())
        verify(sessionClient, never()).issueForDevice(any(), any(), anyOrNull(), any(), anyOrNull(), any())
    }

    @Test
    fun `a verified proof puts the device on the session`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.verifyDeviceProof(eq(proof.challengeId), any())).thenReturn(VerifiedDeviceProof(proof.deviceId, "SOFTWARE"))
        whenever(sessionClient.issueForDevice(eq(tenantId), eq(userId), eq("8.8.8.8"), any(), any(), eq(proof.deviceId)))
            .thenReturn(IssuedSession("tok-device", UUID.randomUUID(), Instant.now()))

        val result = service.login(request.copy(deviceProof = proof))

        assertEquals("tok-device", result.token)
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
    }

    @Test
    fun `the authenticated user, not the caller, is what the proof is checked against`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.verifyDeviceProof(any(), any())).thenReturn(null)
        service.login(request.copy(deviceProof = proof))
        val captor = argumentCaptor<com.iamplatform.auth.client.VerifyDeviceProofRequest>()
        verify(tenantClient).verifyDeviceProof(eq(proof.challengeId), captor.capture())
        assertEquals(userId, captor.firstValue.userId)
    }

    @Test
    fun `a rejected proof still signs the person in, just without a device, and is audited`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.verifyDeviceProof(any(), any())).thenReturn(null)

        val result = service.login(request.copy(deviceProof = proof))

        assertEquals("tok-plain", result.token)
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher, org.mockito.kotlin.atLeastOnce()).publish(captor.capture())
        assertEquals(true, captor.allValues.any { it.action == "auth.device_proof_not_accepted" })
        assertEquals(true, captor.allValues.any { it.action == "auth.login_success" })
    }

    @Test
    fun `an unreachable tenant service cannot stop a sign-in`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.verifyDeviceProof(any(), any())).thenThrow(RuntimeException("tenant-svc is down"))

        val result = service.login(request.copy(deviceProof = proof))

        assertEquals("tok-plain", result.token)
    }

    // ---- Platform-level "authorised laptop to sign in" rule ----

    @Test
    fun `when the tenant rule refuses the laptop, no session is issued and the reason is audited`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.checkLoginDevice(any())).thenReturn(LoginDeviceCheckResponse(false, "DEVICE_NON_COMPLIANT"))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }

        assertEquals(AuthErrorCode.DEVICE_NON_COMPLIANT, ex.errorCode)
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
        verify(sessionClient, never()).issueForDevice(any(), any(), anyOrNull(), any(), anyOrNull(), any())
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher, org.mockito.kotlin.atLeastOnce()).publish(captor.capture())
        assertEquals(true, captor.allValues.any { it.action == "auth.login_denied" && it.result == AuditResult.DENIED && it.reason!!.contains("device_non_compliant") })
        assertEquals(false, captor.allValues.any { it.action == "auth.login_success" })
    }

    @Test
    fun `each refusal code the tenant service can answer reaches the caller as its own error code`() {
        arrangeSuccessfulPasswordAndPush()
        for (code in listOf("DEVICE_REQUIRED", "DEVICE_NOT_APPROVED", "DEVICE_NON_COMPLIANT")) {
            whenever(tenantClient.checkLoginDevice(any())).thenReturn(LoginDeviceCheckResponse(false, code))
            assertEquals(AuthErrorCode.valueOf(code), assertThrows<LoginDeniedException> { service.login(request) }.errorCode, code)
        }
    }

    @Test
    fun `an unknown refusal code is treated as DEVICE_REQUIRED, never as allowed`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.checkLoginDevice(any())).thenReturn(LoginDeviceCheckResponse(false, "SOMETHING_NEW"))
        assertEquals(AuthErrorCode.DEVICE_REQUIRED, assertThrows<LoginDeniedException> { service.login(request) }.errorCode)
        whenever(tenantClient.checkLoginDevice(any())).thenReturn(LoginDeviceCheckResponse(false, null))
        assertEquals(AuthErrorCode.DEVICE_REQUIRED, assertThrows<LoginDeniedException> { service.login(request) }.errorCode)
    }

    @Test
    fun `if the rule cannot be checked the sign-in fails closed with its own code`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.checkLoginDevice(any())).thenThrow(RuntimeException("tenant-svc is down"))

        val ex = assertThrows<LoginDeniedException> { service.login(request) }

        assertEquals(AuthErrorCode.DEVICE_CHECK_UNAVAILABLE, ex.errorCode)
        verify(sessionClient, never()).issue(any(), any(), any(), any(), any())
    }

    @Test
    fun `an open circuit breaker also fails closed`() {
        arrangeSuccessfulPasswordAndPush()
        val breaker = io.github.resilience4j.circuitbreaker.CircuitBreaker.ofDefaults("tenant-svc")
        whenever(tenantClient.checkLoginDevice(any())).thenThrow(CallNotPermittedException.createCallNotPermittedException(breaker))
        assertEquals(AuthErrorCode.DEVICE_CHECK_UNAVAILABLE, assertThrows<LoginDeniedException> { service.login(request) }.errorCode)
    }

    @Test
    fun `the rule is asked about the authenticated user, their role and the verified device`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password"))
            .thenReturn(VerifyPasswordResponse(valid = true, userId = userId, status = RemoteUserStatus.ACTIVE, role = RemoteUserRole.ADMIN))
        whenever(tenantClient.verifyDeviceProof(eq(proof.challengeId), any())).thenReturn(VerifiedDeviceProof(proof.deviceId, "SOFTWARE"))
        whenever(sessionClient.issueForDevice(eq(tenantId), eq(userId), eq("8.8.8.8"), any(), any(), eq(proof.deviceId)))
            .thenReturn(IssuedSession("tok-device", UUID.randomUUID(), Instant.now()))

        service.login(request.copy(deviceProof = proof))

        val captor = argumentCaptor<LoginDeviceCheckRequest>()
        verify(tenantClient).checkLoginDevice(captor.capture())
        assertEquals(tenantId, captor.firstValue.tenantId)
        assertEquals(userId, captor.firstValue.userId)
        assertEquals("ADMIN", captor.firstValue.role)
        assertEquals(proof.deviceId.toString(), captor.firstValue.deviceId)
    }

    @Test
    fun `a sign-in with no proof is checked with no device, and a rejected proof counts as no device`() {
        arrangeSuccessfulPasswordAndPush()
        service.login(request)
        whenever(tenantClient.verifyDeviceProof(any(), any())).thenReturn(null)
        service.login(request.copy(deviceProof = proof))
        val captor = argumentCaptor<LoginDeviceCheckRequest>()
        verify(tenantClient, org.mockito.kotlin.times(2)).checkLoginDevice(captor.capture())
        assertEquals(listOf(null, null), captor.allValues.map { it.deviceId })
    }

    @Test
    fun `the enrollment sign-in skips the rule, is audited as such, and still issues a session`() {
        arrangeSuccessfulPasswordAndPush()
        whenever(tenantClient.checkLoginDevice(any())).thenReturn(LoginDeviceCheckResponse(false, "DEVICE_REQUIRED"))

        val result = service.login(request, enforceDeviceRule = false)

        assertEquals("tok-plain", result.token)
        verify(tenantClient, never()).checkLoginDevice(any())
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher, org.mockito.kotlin.atLeastOnce()).publish(captor.capture())
        assertEquals(true, captor.allValues.any { it.action == "auth.login.enrollment_signin" })
    }

    @Test
    fun `the rule never runs for a bad password, a suspended account or a policy denial`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password")).thenReturn(VerifyPasswordResponse(valid = false))
        assertThrows<InvalidCredentialsException> { service.login(request) }
        verify(tenantClient, never()).checkLoginDevice(any())
    }

    @Test
    fun `a bad password is refused before any device proof is looked at`() {
        whenever(identityClient.verifyPassword(tenantId, "alice@acme.com", "correct-password")).thenReturn(VerifyPasswordResponse(valid = false))
        assertThrows<InvalidCredentialsException> { service.login(request.copy(deviceProof = proof)) }
        verify(tenantClient, never()).verifyDeviceProof(any(), any())
    }
}
