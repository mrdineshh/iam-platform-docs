# Business Requirements Document
## Enterprise Identity & Access Management (IAM) Platform

SSO · Adaptive MFA · Directory Federation · Device Trust · Endpoint Agent

**Document Version:** 1.0
**Status:** Draft for Development (v1 / Multi-Tenant SaaS)

---

## 0. Purpose of this Document

This BRD defines the complete functional and non-functional requirements for the v1 build of a multi-tenant SaaS Identity and Access Management (IAM) platform. It is intended to be handed directly to an engineering/build team (including AI-assisted development tooling) as a self-sufficient specification, minimizing the need for additional clarification during build. Where a requirement has architectural implications beyond the immediate feature, this is called out explicitly as an **Architecture Principle (AP-x)**.

Each functional requirement is numbered (e.g., `FR-3.2`) for traceability. Sections marked **"Out of Scope (v1)"** are intentionally deferred and must NOT be built in v1 — they exist to prevent scope creep and document the target end-state architecture.

---

## 1. Executive Summary

The platform is an enterprise-grade Identity and Access Management (IAM) system providing Single Sign-On (SSO) to any SaaS or web application, directory federation (Active Directory, Entra ID, and any SAML/OIDC-capable IdP), a unified adaptive authentication engine (password, passwordless, multi-factor), contextual/risk-based access control (IP, geo-location, device trust), a managed endpoint agent (device posture enforcement, tamper-resistant uninstall, corporate/personal Google account separation), full white-label branding, granular RBAC, and enterprise-grade audit, compliance, and availability guarantees.

v1 will be delivered as a multi-tenant SaaS product. Dedicated single-tenant and on-premise deployment models are explicitly planned for later phases and must not block or complicate the v1 architecture, but the core system must be built in a deployment-agnostic manner (containerized, config-driven tenancy, no hard cloud-vendor lock-in) so those phases are extensions, not rewrites.

This document is the single source of truth for v1 build scope. **Anything not explicitly listed as in-scope should be treated as out of scope for v1.**

---

## 2. Scope

### 2.1 In Scope (v1)

- SSO integration with any SaaS/web application via SAML 2.0 and OIDC
- Federation with customer-owned directories: Entra ID, on-prem Active Directory (with or without ADFS), and generic SAML/OIDC IdPs
- SCIM 2.0 based lifecycle provisioning/deprovisioning, alongside JIT (authentication-only) provisioning
- Multi-directory support per tenant, with identity collision detection and resolution workflow
- Unified authentication factor engine: password, FIDO2/WebAuthn (passkeys), push notification, TOTP, SMS OTP, Email OTP
- Password policy engine (complexity, history, optional rotation, breached-password screening, lockout)
- Adaptive / risk-based authentication (step-up MFA triggered by contextual risk signals)
- Contextual access control: IP restriction, geo-location restriction (country/region/city + agent-based precise GPS), device-based restriction — each enforceable at Tenant, OU/Group, and User level with a configurable merge/override model and tenant-level hard-caps
- Continuous, in-session policy re-evaluation (not just login-time) with automatic session termination on violation
- Edge/WAF-level geo-IP restriction of the tenant login (SSO) URL itself, paired with a mandatory break-glass emergency access mechanism
- Cross-platform (Windows, macOS, Linux) endpoint agent: device trust (TPM/Secure Enclave-backed certificate, hardware-fingerprint fallback), continuous posture checks, GPS-based geo-restriction, tamper-resistant and remotely-authorized uninstall only
- Corporate-vs-personal Google account access control (Chrome/Edge native enterprise policy; agent-enforced block/redirect for non-Chromium browsers), configurable per tenant
- Fully customizable login page (theme, color, logo) on a platform subdomain
- Granular, custom, OU/group-scoped RBAC from day one
- Mobile Authenticator app (iOS/Android) for push, TOTP, and passkey-related flows
- Admin reporting/analytics dashboards
- Service-account/API-key based programmatic API access
- Full audit logging (user activity, admin activity, security events) with 1-year active retention and archive-on-request thereafter
- SOC 2 Type II, ISO 27001, and GDPR-aligned compliance baseline
- 99.99% application-level availability target

### 2.2 Out of Scope (v1) — Explicitly Deferred

These are documented as target end-state architecture but must **NOT** be built in v1. See Section 10 for the phased roadmap.

- Dedicated single-tenant deployment model
- On-premise deployment model
- Custom customer-owned domains for the login page (e.g., `login.customer.com`) — v1 is subdomain-only
- Multi-region data residency options
- TLS-inspecting/decrypting proxy for general traffic (explicitly rejected as an approach — see Section 6.6)
- Publicly self-registerable developer API / API marketplace
- Voice-call OTP, magic links, and grid-card authentication factors (explicitly excluded, not deferred)

---

## 3. Definitions & Glossary

| Term | Definition |
|---|---|
| **IdP** | Identity Provider — the system that authenticates a user and asserts identity (e.g., Entra ID, on-prem AD via ADFS, or the platform itself acting as IdP to downstream apps). |
| **SP** | Service Provider — the application relying on an IdP assertion to grant access (e.g., a downstream SaaS app, or the platform when federating with a customer's upstream directory). |
| **Identity Broker / IdP Chaining** | The pattern where the platform acts simultaneously as an SP (to the customer's upstream AD/Entra) and an IdP (to downstream integrated applications). |
| **Delegated Authentication** | Upstream directory (AD/Entra) proves "who the user is" (identity proofing); the platform independently and always enforces its own policy layer (MFA, geo, IP, device) on top — an upstream assertion never directly creates a session. |
| **PEP** | Policy Enforcement Point — the gateway/proxy layer that all traffic to protected apps routes through, which continuously re-validates session context (IP, geo, device) in real time. |
| **JIT Provisioning** | Just-In-Time provisioning — a user record is created in the platform automatically on their first successful login via a federated IdP. |
| **SCIM** | System for Cross-domain Identity Management — the industry-standard protocol for full user lifecycle sync (create/update/disable/delete) between a directory and the platform. |
| **Hard-cap Policy** | A tenant-level policy marked as non-overridable by any lower-level (OU/group/user) policy, regardless of the standard merge/override rules. |
| **Break-glass Access** | An out-of-band, separately authenticated, heavily audited emergency access path that is exempt from the standard geo/IP edge block, used solely for account recovery when the primary access path is unreachable. |
| **Device Trust / Device Posture** | The set of signals (TPM/Secure Enclave certificate, hardware fingerprint, OS patch level, disk encryption, EDR/AV status, jailbreak/root status, agent tamper status) used to determine whether a device is trusted and compliant. |
| **TPM** | Trusted Platform Module — a hardware security chip that generates and stores cryptographic keys such that they cannot be extracted, even with administrative access to the host device. |
| **Adaptive / Risk-Based Authentication** | Authentication that dynamically requires additional factors (step-up) based on real-time risk signals, rather than a static always-on/always-off MFA rule. |
| **Impossible Travel** | A risk signal triggered when a user's successive login locations are geographically impossible to reach within the elapsed time between logins. |
| **Tenant** | A single customer organization onboarded onto the multi-tenant SaaS platform, with isolated data, policies, and branding. |
| **OU** | Organizational Unit — a grouping construct (synced from the customer's directory via SCIM/AD/Entra) used to scope policies and RBAC roles below the tenant level. |

---

## 4. Cross-Cutting Architecture Principles

These principles apply across every functional module and must not be violated by any individual feature implementation.

**AP-1: Unified Authentication Engine**
Password login, passwordless login, MFA, and adaptive/step-up authentication are NOT separate code paths. They are all policy-driven combinations produced by one factor engine and one policy engine. "Passwordless" is simply a policy that permits login using only a strong factor (FIDO2/push), skipping password entry.

**AP-2: Policy Enforcement Point (PEP), Not Login-Only Checks**
IP, geo, and device policies are not evaluated only at login. All traffic to protected applications routes through the platform's PEP (gateway/reverse-proxy layer), which continuously re-validates session context against policy and can terminate a session mid-flight, in real time, on violation.

**AP-3: Never Trust an Upstream IdP Assertion Directly**
When a customer's AD/Entra/ADFS acts as the upstream identity source, its assertion proves identity only. It must always pass through the platform's own policy engine (MFA, geo, IP, device, adaptive risk) before a session is created. The platform is always the final authority on session issuance.

**AP-4: Policy Resolution Model — Merge with Hard-Caps**
Policies exist at Tenant, OU/Group, and User level. A more specific level (User) overrides a broader level (OU/Group) only for the specific attributes it defines; anything it does not define is inherited from the broader level (a merge, not a full override). Tenant admins may additionally mark specific policies (e.g., country blocklists) as "hard-cap" / non-overridable, which no lower level can loosen, regardless of the standard merge rule.

**AP-5: Deployment-Agnostic Core**
The core platform must be built containerized and config-driven for tenancy, with no hard dependency on a specific cloud vendor's proprietary services where reasonably avoidable. This is required so that Phase 2 (dedicated single-tenant) and Phase 3 (on-prem) are deployment variations of the same codebase, not rewrites, even though only the multi-tenant SaaS model is built in v1.

**AP-6: Attribute Mapping Is a Configurable, Versioned Layer**
Directory attribute-to-platform-attribute mapping must be implemented as a schema/config-driven engine, not hardcoded per integration. The v1 self-service mapping UI is a front-end over this engine, not a separate system.

**AP-7: The Agent Is a Policy/Posture/Network-Control Agent — Not a Blanket TLS-Inspecting Proxy**
The endpoint agent enforces device posture, GPS-based geo-restriction, and native browser enterprise policies (or targeted domain-level block/redirect). It must not implement general-purpose TLS decryption/inspection of user traffic. This keeps the security/legal posture defensible and avoids the reliability problems of certificate-pinning breakage.

**AP-8: Every Uninstall and Every Policy Bypass Is Fully Audited**
Break-glass access usage and agent uninstall authorization must produce an immutable audit record: who, what, which device/tenant, and when.

---

## 5. Functional Requirements

### 5.1 SSO & Application Integration

- **FR-1.1** The platform shall support SAML 2.0 as a first-class protocol for integrating with any SaaS or web application, acting as the Identity Provider (IdP) to the downstream application (Service Provider).
- **FR-1.2** The platform shall support OpenID Connect (OIDC) as a first-class protocol, equivalent in priority to SAML 2.0.
- **FR-1.3** The platform shall support OAuth 2.0 for API-level delegated authorization scenarios.
- **FR-1.4** The platform shall maintain a configurable application catalog per tenant, allowing an admin to add, configure, and remove SSO integrations for individual applications.
- **FR-1.5** WS-Federation support is not required for v1 and should be deferred unless a specific legacy-integration need arises.

### 5.2 Directory & Identity Sourcing

**5.2.1 Upstream Identity Broker Model**

- **FR-2.1** The platform shall support acting as a Service Provider (SP) relative to a customer's upstream identity source (Entra ID, on-prem AD via ADFS, or on-prem AD directly) and simultaneously as an Identity Provider (IdP) to all downstream integrated applications (Identity Broker / IdP-chaining pattern).
- **FR-2.2** For Entra ID as the upstream source: the platform shall support standard SAML/OIDC federation via a per-tenant Entra Enterprise App registration, with configurable claims/attribute mapping and JIT provisioning on first login.
- **FR-2.3** For on-prem Active Directory WITH ADFS: the platform shall federate with ADFS as a standard SAML/WS-Fed IdP, equivalent in pattern to the Entra case.
- **FR-2.4** For on-prem Active Directory WITHOUT ADFS: the platform shall provide a lightweight on-prem directory connector/agent (distinct from the endpoint device agent — see Section 5.5) that performs LDAP bind / Kerberos validation against AD inside the customer's network and relays results to the cloud platform over an outbound-only secure channel. No inbound connection to the customer's private network is required.
- **FR-2.5** [AP-3] Regardless of upstream source, the platform's own policy engine (MFA, geo, IP, device, adaptive risk) shall always evaluate and control session issuance. The upstream source only proves identity ("Layer 1"); the platform's policy layer ("Layer 2") always governs authorization.

**5.2.2 Provisioning & Lifecycle**

- **FR-2.6** The platform shall support authentication-only integration (JIT provisioning at first login) for tenants that do not require lifecycle sync.
- **FR-2.7** The platform shall support full lifecycle management via SCIM 2.0 (create, update, disable, delete) for tenants requiring real-time deprovisioning, independent of and simultaneously available alongside JIT provisioning.
- **FR-2.8** Both modes (JIT-only and full SCIM lifecycle) shall be simultaneously supportable within the same platform, selectable per tenant and per directory source.

**5.2.3 Multi-Directory & Attribute Sync**

- **FR-2.9** The platform shall support multiple directory sources connected to a single tenant simultaneously (e.g., Entra ID for HQ staff and a separate on-prem AD forest for a subsidiary), from the initial v1 data model.
- **FR-2.10** The platform shall implement identity collision detection: when the same individual appears to exist across more than one connected directory source (matched via a configurable unique attribute, e.g., email or employeeID), the platform shall flag the conflict for manual admin resolution. Silent automatic merging is prohibited.
- **FR-2.11** [AP-6] The platform shall implement a centralized, schema/config-driven attribute mapping and sync engine ensuring consistent user attributes across the platform and all downstream application integrations (single source of truth for reporting).
- **FR-2.12** OU/Group membership shall be synced from connected directory sources and made available for use in policy scoping (Section 5.4) and RBAC scoping (Section 5.7).

**5.2.4 Self-Service**

- **FR-2.13** Tenant admins shall have a self-service interface for configuring directory connections and attribute mappings (front-ended over the AP-6 mapping engine).
- **FR-2.14** End users shall have a self-service portal for password reset and MFA/passkey enrollment and device management (see also Section 5.3).

### 5.3 Authentication Policy Engine

**5.3.1 Password Policy**

- **FR-3.1** The platform shall support configurable password complexity rules (minimum length, character class requirements) per tenant.
- **FR-3.2** The platform shall support configurable password history, preventing reuse of the last N passwords (N configurable per tenant).
- **FR-3.3** The platform shall support optional, configurable password rotation/expiry. Default posture is OFF (aligned with NIST 800-63B guidance); tenants with compliance obligations requiring periodic rotation may enable it.
- **FR-3.4** The platform shall screen new passwords against a breached-password database (HIBP-style API integration or equivalent) and reject known-compromised passwords.
- **FR-3.5** The platform shall support configurable account lockout policy: failed-attempt threshold, lockout duration, and a permanent-lock state requiring admin unlock.

**5.3.2 Unified Factor Framework**

- **FR-3.6** [AP-1] The platform shall implement one unified authentication factor engine supporting: FIDO2/WebAuthn (passkeys, hardware keys, platform biometrics), push notification (approve/deny via the Mobile Authenticator app), TOTP, SMS OTP, and Email OTP.
- **FR-3.7** Magic-link authentication is explicitly excluded from the platform and must not be implemented.
- **FR-3.8** FIDO2/WebAuthn shall be positioned as the primary/recommended strong factor across passwordless and MFA policy configurations.
- **FR-3.9** SMS OTP shall be flagged in the admin UI as a lower-assurance factor and shall be independently toggleable (enable/disable) per tenant policy.
- **FR-3.10** Passwordless login shall be implemented purely as a policy configuration of the unified factor engine (permitting login via a strong factor alone, without password), not as a separate authentication subsystem.

**5.3.3 Adaptive / Risk-Based Authentication**

- **FR-3.11** The platform shall implement a risk-scoring model (not static boolean rules) evaluating contextual signals including: new/unrecognized device, impossible travel, anomalous IP/network, and unrecognized location.
- **FR-3.12** Based on the computed risk score, the platform shall dynamically trigger step-up authentication (requiring an additional/stronger factor), rather than applying a single static MFA rule to all logins.
- **FR-3.13** Risk signals used for adaptive authentication shall be sourced from the same contextual data used for IP/geo/device policy enforcement (Section 5.4), avoiding duplicate signal-collection logic.

### 5.4 Contextual Access Control

**5.4.1 Policy Scoping & Resolution**

- **FR-4.1** IP, geo-location, and device policies shall each be configurable at three levels: Tenant/Org, OU/Group (synced from directory — FR-2.12), and individual User.
- **FR-4.2** [AP-4] Policy resolution shall follow the merge-with-hard-cap model: a more specific level overrides a broader level only for attributes it explicitly defines; unspecified attributes are inherited. Tenant admins may mark specific policies as non-overridable hard-caps, which apply regardless of lower-level configuration.

**5.4.2 IP-Based Restriction**

- **FR-4.3** The platform shall support IP allow/deny lists (CIDR ranges), scoped per FR-4.1.
- **FR-4.4** [AP-2] IP restriction shall be continuously enforced for the full session duration via the PEP, not evaluated only at login. If a session's source IP changes to a non-compliant network after login, the platform shall terminate that session immediately.

**5.4.3 Geo-Location Restriction**

- **FR-4.5** The platform shall support geo-restriction by country, region/state, and city, using IP-geolocation as the standard, always-available signal for both agent-managed and unmanaged (browser-only) access.
- **FR-4.6** The platform shall support impossible-travel detection as a dynamic risk signal (feeding FR-3.11), flagging or blocking logins that are physically impossible given the time elapsed since the previous login location.
- **FR-4.7** Precise GPS-based (latitude/longitude) geo-restriction and continuous location monitoring shall be available exclusively on agent-managed devices (via the endpoint agent reading device location services), not attempted for unmanaged/browser-only access, due to the inherent imprecision of IP-geolocation for lat/long-level accuracy.
- **FR-4.8** On agent-managed devices, geo-location shall be continuously monitored (not just at login); the platform shall be able to terminate the session immediately upon detecting the device has left the permitted geographic boundary.

**5.4.4 Device-Based Restriction**

- **FR-4.9** See Section 5.5 (Endpoint Agent) for full device trust and posture requirements. Device-based access policy shall be scoped and resolved per FR-4.1/FR-4.2, identical to IP and geo policy.

**5.4.5 SSO Login URL Edge Restriction**

- **FR-4.10** The platform shall support an edge/WAF-level geo-IP restriction on the tenant's SSO login portal URL itself, such that connections from non-whitelisted countries/regions/IP ranges are rejected at the network edge (the login page does not load), not merely rejected after an application-level policy evaluation.
- **FR-4.11** [Mandatory] The platform shall provide a break-glass emergency access mechanism: a separate, out-of-band access path (distinct URL and/or distinct authentication flow) that is exempt from the FR-4.10 edge block, protected by stronger authentication, and subject to heightened audit logging and alerting. This exists specifically to prevent tenant admins from being irrecoverably locked out by their own edge-geo-block misconfiguration.

### 5.5 Endpoint Agent

**5.5.1 Platform Support**

- **FR-5.1** The endpoint agent shall support Windows, macOS, and Linux.

**5.5.2 Device Trust / Identity**

- **FR-5.2** At agent installation, the agent shall establish device identity using a hardware-backed cryptographic key: TPM-backed key + platform-issued X.509 certificate on Windows/Linux (where TPM is available), or the equivalent Secure Enclave mechanism on macOS. This key must not be extractable from the device, including by an administrator with root/local admin access.
- **FR-5.3** For devices without a usable TPM/Secure Enclave (e.g., older hardware, some Linux configurations), the platform shall fall back to a composite hardware fingerprint (BIOS serial + disk serial + MAC address + CPU ID). Devices relying on this fallback shall be flagged in the admin console as "lower assurance" and may be subject to additional policy restrictions (e.g., mandatory extra MFA) at tenant discretion.

**5.5.3 Continuous Posture Signals**

- **FR-5.4** The agent shall continuously report device posture, including: OS patch/update level, disk encryption status (BitLocker/FileVault/LUKS), presence and status of EDR/antivirus software, jailbreak/root detection, and detection of tampering with the agent itself.
- **FR-5.5** The agent shall continuously report device GPS-based location for geo-restriction enforcement per FR-4.7/FR-4.8.

**5.5.4 Corporate vs. Personal Google Account Restriction**

- **FR-5.6** The platform shall support restricting personal @gmail.com account access on managed devices while permitting the corporate Google Workspace account, configurable per tenant based on which browsers the tenant needs covered.
- **FR-5.7** For Chrome and Edge (Chromium-based browsers): the agent shall push and continuously verify the native Chromium enterprise sign-in-restriction policy (e.g., RestrictSigninToPattern-equivalent), which blocks personal Google account sign-in at the browser level without any traffic decryption.
- **FR-5.8** For Firefox or any browser not supporting the native Chromium policy: the agent shall enforce at the network/host level, blocking or redirecting access to Google authentication domains and prompting the user to switch to a managed (Chrome/Edge) browser.
- **FR-5.9** [AP-7] A general-purpose TLS-inspecting/decrypting proxy shall NOT be built for this or any other use case. All traffic-level enforcement by the agent must be scoped, policy-based, and domain/host-targeted.

**5.5.5 Tamper-Resistant, Remotely-Authorized Uninstall**

- **FR-5.10** The agent shall not be uninstallable via any static local password or key, including admin-generated ones.
- **FR-5.11** Agent uninstall shall require a remote, admin-initiated unlock: a tenant admin selects the specific device in the platform console and triggers a signed, time-limited, single-use uninstall token scoped to that device only. Uninstall may proceed only within that authorized window on that specific device.
- **FR-5.12** Agent uninstall authorization requires the device to be online and able to reach the platform to retrieve the unlock token. No offline/air-gapped uninstall path shall be provided — this is an intentional security control, consistent with industry-standard enterprise EDR agent behavior.
- **FR-5.13** [AP-8] Every uninstall authorization event shall produce an immutable audit record: authorizing admin, target device, tenant, and timestamp.

### 5.6 Branding & Login Page Customization

- **FR-6.1** Tenant admins shall be able to customize the login page theme, color scheme, and logo at any time via self-service configuration.
- **FR-6.2** The login page shall be served exclusively on a subdomain of the platform's own domain (e.g., `tenant.platform-domain.com`). Custom customer-owned domains are out of scope for v1 (see Section 2.2) to avoid DNS/SSL support liability shifting onto the platform vendor.

### 5.7 Admin, RBAC & Tenant Architecture

**5.7.1 Deployment Model (v1)**

- **FR-7.1** [AP-5] v1 shall be delivered exclusively as a multi-tenant SaaS product, built on a deployment-agnostic core architecture so that dedicated single-tenant and on-premise models (Section 10 roadmap) can be added later without a rewrite.

**5.7.2 RBAC**

- **FR-7.2** The platform shall provide a baseline admin hierarchy: Platform Super Admin (vendor-level, manages all tenants/billing/platform health) → Tenant Admin (full control of their own tenant) → Custom Scoped Roles.
- **FR-7.3** The platform shall support granular, custom RBAC from v1 launch: tenant admins can create custom roles with fine-grained permission sets, not limited to a fixed predefined role list.
- **FR-7.4** Custom roles shall support OU/Group scoping: an admin assigned to a specific OU can only manage policies, restrictions, and users within that OU, not tenant-wide, unless explicitly granted tenant-wide scope.

### 5.8 Mobile Authenticator App

- **FR-8.1** The platform shall provide a companion Mobile Authenticator app (iOS and Android) supporting push-notification approve/deny, TOTP code display, and passkey-related flows.

### 5.9 Reporting & Analytics

- **FR-9.1** The platform shall provide admin-facing reporting/analytics dashboards covering login trends, risk/adaptive-auth events, and compliance-relevant reports, available in v1.

### 5.10 API & Programmatic Access

- **FR-10.1** The platform shall expose an API for provisioning automation, policy/configuration management, and audit log retrieval, authenticated via tenant-issued service accounts / API keys.
- **FR-10.2** The API shall not be a publicly self-registerable developer API / marketplace in v1; access is limited to credentials explicitly issued by a tenant admin for their own integrations.

### 5.11 Audit Logging

- **FR-11.1** The platform shall log full user activity (application access events, login/logout, session lifecycle events), full admin activity (all configuration and policy changes), and all security events (MFA/step-up triggers, break-glass usage, agent uninstall authorizations, policy violations and session terminations).
- **FR-11.2** Audit logs shall be retained in active, searchable storage for 1 year by default, after which they shall be purged to archive storage and remain retrievable on request (not permanently deleted).

> **Note:** This is a materially larger data volume than security-event-only logging, since every application access event is included, not just security-relevant events. Storage/indexing architecture must account for this scale from the outset.

---

## 6. Key Design Decisions & Rationale

**6.1 Why the AD/Entra Integration Splits Into Two Patterns**
On-prem AD speaks LDAP/Kerberos, not SAML/OIDC, and should never be exposed directly to the internet. Entra ID and ADFS both natively speak SAML/OIDC/WS-Fed and integrate via standard federation. Plain on-prem AD (no ADFS) requires a separate lightweight on-prem connector distinct from the endpoint device agent.

**6.2 Why Delegated Authentication, Not Full Pass-Through**
If an upstream IdP assertion could directly create a platform session, the platform's own MFA/geo/IP/device policies could be bypassed entirely by compromising the upstream IdP alone. The platform must always retain final authority over session issuance.

**6.3 Why SCIM Alongside JIT, Not SCIM Instead of JIT**
JIT provisioning only creates users at first login and has no knowledge of terminations. SCIM provides real-time lifecycle sync (critical for timely deprovisioning, a common SOC 2 audit finding) but is heavier to configure. Supporting both, selectable per tenant, avoids forcing a tradeoff the customer shouldn't have to make.

**6.4 Why One Unified Factor/Policy Engine Instead of Separate Passwordless/MFA Systems**
Building passwordless, MFA-on-top-of-password, and adaptive step-up as separate systems multiplies engineering and QA surface area and creates drift between them over time. Treating them as policy configurations of one engine means new factors or policy combinations do not require new code paths.

**6.5 Why TPM/Secure-Enclave-Backed Certificates Instead of BIOS Serial Number**
A BIOS serial is a readable/editable firmware string with no cryptographic guarantee — it can be spoofed and proves nothing about current device compromise status. A TPM- or Secure-Enclave-backed key cannot be extracted even with root/administrator access, providing genuine cryptographic proof of physical device identity, and forms the basis of a real zero-trust device posture model.

**6.6 Why No General TLS-Inspecting Proxy**
A TLS-decrypting proxy for the Google-account-separation use case (or any other) requires installing a root certificate on every device, breaks certificate pinning in some applications, faces active countermeasures from providers, and creates significant trust/legal exposure from decrypting user HTTPS traffic. The native Chromium enterprise policy mechanism achieves the same outcome for Chrome/Edge with far greater reliability and no decryption; Firefox is handled via targeted domain-level blocking/redirection instead of extending decryption to cover it.

**6.7 Why Uninstall Requires Online, Admin-Authorized Action With No Offline Exception**
A static local uninstall password (even admin-issued) risks leakage and reuse across devices. An offline uninstall exception would allow an attacker (or a user seeking to evade monitoring) to disconnect a device from the network specifically to remove the agent without authorization. Requiring an online, single-use, device-specific, remotely-issued token closes this vector and matches the standard behavior of established enterprise EDR agents (e.g., CrowdStrike, SentinelOne), which SOC 2/ISO auditors generally view favorably rather than as a limitation.

**6.8 Why Subdomain-Only Branding for v1**
Custom customer-owned domains shift DNS configuration, propagation, and SSL certificate issuance/renewal risk onto the platform vendor's support burden, while customers typically attribute any resulting failure to the platform itself rather than their own DNS/domain management. Subdomain-only branding removes this failure class entirely for v1.

**6.9 Why a Mandatory Break-Glass Path for the Edge Geo-Block**
A hard edge-level geo-IP block with no exception path risks irrecoverable tenant admin lockout from a single misconfiguration (e.g., a corporate VPN egress point in an unexpected country), with no way to reach the login page to self-correct. A separately authenticated, heavily audited break-glass path is standard practice among established IAM vendors for exactly this reason.

---

## 7. Non-Functional Requirements

### 7.1 Availability & Resilience

- **NFR-1.1** The platform shall target 99.99% application-level availability. Since the platform is the authentication gateway for a tenant's entire integrated application ecosystem, an outage effectively locks tenants out of all downstream apps — availability engineering must be treated with the same rigor as a critical-path system, not a typical SaaS backend.
- **NFR-1.2** Resilience (multi-instance deployment, no single point of failure, graceful degradation, health checks, circuit breakers on downstream dependencies such as SCIM/AD connectors) is an application/architecture-level responsibility.
- **NFR-1.3** Underlying infrastructure redundancy (multi-AZ, etc.) is delegated to the Cloud Service Provider (CSP) and is not a custom engineering deliverable.

### 7.2 Compliance

- **NFR-2.1** The platform shall be architected to support SOC 2 Type II, ISO 27001, and GDPR compliance as the general enterprise baseline (data residency/right-to-erasure considerations under GDPR).
- **NFR-2.2** Industry-specific frameworks (e.g., HIPAA, PCI-DSS) are out of scope for v1 unless a specific customer requirement introduces them in a later phase.

### 7.3 Audit & Logging

- **NFR-3.1** See FR-11.1/FR-11.2 (Section 5.11) for full audit logging scope and retention requirements.

### 7.4 Data Residency

- **NFR-4.1** v1 shall use single-region hosting. Multi-region data residency options (e.g., EU-only storage for EU tenants) are deferred to a later phase (see Section 10).

### 7.5 Security

- **NFR-5.1** All cryptographic key material for device trust (Section 5.5.2) must be hardware-bound and non-exportable wherever TPM/Secure Enclave is available.
- **NFR-5.2** All administrative actions affecting policy, RBAC, break-glass access, and agent uninstall authorization must be logged immutably (see AP-8).

### 7.6 Scalability

- **NFR-6.1** The platform shall support standard enterprise-IAM-grade elasticity (auto-scaling infrastructure), without a fixed hard limit on tenant count, users per tenant, or peak concurrent logins baked into the architecture.

### 7.7 Open-Source Licensing & Vendor Sustainability

Given the on-premise deployment phase (Section 10) and the deployment-agnostic core principle (AP-5), all third-party infrastructure dependencies must be reviewed for license terms and maintenance sustainability before adoption, not just at initial selection.

- **NFR-7.1** No infrastructure dependency shall be adopted under a license that restricts using it to build or operate a commercial hosted product (e.g., source-available licenses such as BUSL, SSPL, or RSAL), given the platform is itself a commercial product the customer may eventually run on-premise or as a dedicated instance.
- **NFR-7.2** No infrastructure dependency shall be adopted if its upstream project is unmaintained or formally retired/end-of-life, regardless of license terms, since this creates unpatched security exposure over time.
- **NFR-7.3** This review is not a one-time gate: license terms and maintenance status of adopted dependencies shall be periodically re-checked, since vendors have historically changed license terms on previously-safe dependencies with limited notice (e.g., Redis, HashiCorp Terraform/Vault).
- **NFR-7.4** Internal-use observability/ops tooling under copyleft network-use licenses (e.g., AGPLv3) is acceptable, since the copyleft obligation triggers only if the tool is modified and re-offered as a service to others — which does not apply to internal operational tooling. This exception does not extend to any dependency embedded in a customer-facing feature.

---

## 8. Assumptions & Dependencies

- Customers using on-prem AD without ADFS will permit installation of the on-prem directory connector within their network, with outbound-only connectivity to the platform.
- Customers requiring the corporate/personal Google account separation feature will deploy the endpoint agent (or Chrome/Edge enterprise management) on managed devices; the feature has no equivalent for entirely unmanaged/BYOD devices.
- A third-party breached-password-check API (HIBP or equivalent) is available and its use is acceptable to customers from a data-handling perspective (only password hashes/prefixes are checked, not plaintext passwords, per standard k-anonymity API design).
- A third-party IP-geolocation database/service is available and its accuracy is acceptable for country/region/city-level enforcement (with known limitations for cloud-hosted/VPN-exit IP ranges, as discussed in Section 6).
- Devices used for GPS-based precise geo-restriction have location services enabled and accessible to the agent, subject to OS-level permission models.
- A Cloud Service Provider (CSP) will be selected to provide infrastructure-level redundancy in support of the 99.99% availability target (NFR-1.3); CSP selection itself is outside the scope of this BRD.

---

## 9. Risk & Mitigation Register

| # | Risk | Mitigation |
|---|---|---|
| R1 | SMS OTP is vulnerable to SIM-swap attacks | Flagged as lower-assurance (FR-3.9), independently toggleable per tenant; adaptive engine (FR-3.11) can require step-up beyond SMS for high-risk actions |
| R2 | IP-geolocation is imprecise for cloud-hosted/VPN-exit IP ranges, risking false policy blocks | Break-glass mechanism (FR-4.11) as a safety valve; hard-caps (AP-4) should be applied conservatively at country level, not narrow IP ranges, unless validated per-tenant |
| R3 | TPM/Secure Enclave unavailable on some Linux configurations and older hardware | Hardware-fingerprint fallback (FR-5.3), explicitly flagged as lower-assurance, tenant may require additional MFA on these devices |
| R4 | Online-only agent uninstall (FR-5.12) could block legitimate decommissioning of a device that is lost, stolen, or destroyed and will never come back online | Admin can revoke a device's trust/session record on the platform side independently of physical agent uninstall — the device is denied access immediately even if the agent binary is never formally removed. This is an accepted operational tradeoff, not a gap. |
| R5 | Third-party open-source dependencies may change license terms after adoption (precedent: Redis, HashiCorp Terraform/Vault) | NFR-7.1–7.3 — periodic re-review of license and maintenance status, not just a one-time check at selection |
| R6 | The break-glass emergency access path (FR-4.11) could itself become an attack target if discovered | Heightened audit logging and alerting (already required by FR-4.11) plus rate-limiting and restriction to pre-registered recovery contacts/methods, to be detailed in that module's implementation spec |
| R7 | Silent identity merging across multiple connected directories could incorrectly conflate two different people | Explicitly prohibited — FR-2.10 requires manual admin resolution of any collision, never automatic merge |
| R8 | Single-region hosting (v1, NFR-4.1) creates latency and data-residency exposure for tenants far from the hosting region or under strict residency requirements | Accepted v1 tradeoff; multi-region is deferred, not precluded (Section 10 roadmap) |
| R9 | Continuous session policy re-evaluation (AP-2) could add latency to every request if not designed carefully | Redis/Valkey-backed low-latency policy cache; the implementation spec for the PEP module must define acceptable latency budgets before build |
| R10 | Autonomous AI-driven development could drift from architecture principles over a long build without human review at every step | `/CLAUDE.md` + `/docs/ENGINEERING_GUARDRAILS.md` — explicit autonomy tiers (what can be decided alone vs. must be flagged), mandatory interview-then-spec per module, and a Definition of Done requiring explicit negative-case tests for security-sensitive modules |

---

## 10. Phased Roadmap

Only the **V1** column represents current build scope. Phase 2 and Phase 3 items must not be built now but must not be architecturally precluded (see AP-5).

| Area | V1 (Build Now) | Phase 2 | Phase 3 |
|---|---|---|---|
| Deployment model | Multi-tenant SaaS | Dedicated single-tenant | On-premise |
| Login domain | Platform subdomain only | Custom customer domain (evaluate) | — |
| Data residency | Single region | — | Multi-region / customer-chosen residency |
| Directory integration | Entra, ADFS, on-prem AD (w/ connector), SCIM, multi-directory | — | — |
| Attribute mapping UI | Self-service (built on config-driven engine) | — | — |

---

## 11. Requirement Numbering Reference

| Prefix | Section |
|---|---|
| FR-1.x | SSO & Application Integration |
| FR-2.x | Directory & Identity Sourcing |
| FR-3.x | Authentication Policy Engine |
| FR-4.x | Contextual Access Control |
| FR-5.x | Endpoint Agent |
| FR-6.x | Branding & Login Page Customization |
| FR-7.x | Admin, RBAC & Tenant Architecture |
| FR-8.x | Mobile Authenticator App |
| FR-9.x | Reporting & Analytics |
| FR-10.x | API & Programmatic Access |
| FR-11.x | Audit Logging |
| NFR-x.x | Non-Functional Requirements (7.7 specifically: Open-Source Licensing & Vendor Sustainability) |
| AP-x | Cross-Cutting Architecture Principles (Section 4) |
