package com.iamplatform.tenant

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

interface OidcClientGroupRepository : JpaRepository<OidcClientGroupEntity, UUID> {
    fun findByOidcClientId(oidcClientId: UUID): List<OidcClientGroupEntity>

    fun findByGroupId(groupId: UUID): List<OidcClientGroupEntity>

    @Transactional
    fun deleteByOidcClientId(oidcClientId: UUID)

    @Transactional
    fun deleteByGroupId(groupId: UUID)
}

interface SamlSpGroupRepository : JpaRepository<SamlSpGroupEntity, UUID> {
    fun findBySamlSpId(samlSpId: UUID): List<SamlSpGroupEntity>

    fun findByGroupId(groupId: UUID): List<SamlSpGroupEntity>

    @Transactional
    fun deleteBySamlSpId(samlSpId: UUID)

    @Transactional
    fun deleteByGroupId(groupId: UUID)
}
