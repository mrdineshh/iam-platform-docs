package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals

class MeControllerTest {

    private val adminAccessGuard = mock<AdminAccessGuard>()
    private val identityClient = mock<IdentityClient>()
    private val controller = MeController(adminAccessGuard, identityClient)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()

    private fun givenSession() {
        whenever(adminAccessGuard.requireValidSession("tok"))
            .thenReturn(RemoteSession(UUID.randomUUID(), tenantId, userId, Instant.now().plusSeconds(3600)))
    }

    @Test
    fun `returns the signed-in user's own name and email, taken from the session`() {
        givenSession()
        whenever(identityClient.findUser(userId))
            .thenReturn(RemoteUser(userId, tenantId, RemoteUserRole.USER, email = "ada@econz.net", displayName = "Ada Lovelace"))

        val me = controller.me("tok").body!!

        assertEquals(userId, me.id)
        assertEquals("ada@econz.net", me.email)
        assertEquals("Ada Lovelace", me.displayName)
        assertEquals(RemoteUserRole.USER, me.role)
    }

    @Test
    fun `a session whose user no longer exists is treated as invalid`() {
        givenSession()
        whenever(identityClient.findUser(userId)).thenReturn(null)

        assertThrows<AdminSessionInvalidException> { controller.me("tok") }
    }

    @Test
    fun `an unknown session is rejected before any user lookup`() {
        whenever(adminAccessGuard.requireValidSession("bad")).thenThrow(AdminSessionInvalidException())

        assertThrows<AdminSessionInvalidException> { controller.me("bad") }
    }
}
