package com.iamplatform.oidc

/**
 * GET /authorize's direct error page for an invalid/unregistered request --
 * the only HTML this service renders now that the login form itself has
 * moved to iam-login-portal (Service 13). See docs/DECISIONS.md, Service 13
 * pre-implementation entry.
 */
object LoginFormRenderer {

    fun renderError(message: String): String = """
        <!DOCTYPE html>
        <html><body style="font-family: sans-serif; max-width: 480px; margin: 80px auto;">
          <h2>Sign-in request could not be processed</h2>
          <p>${escape(message)}</p>
        </body></html>
    """.trimIndent()

    private fun escape(value: String): String =
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
}
