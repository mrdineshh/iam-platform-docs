package com.iamplatform.audit

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(AuditKafkaDlqProperties::class)
class IamAuditSvcApplication

fun main(args: Array<String>) {
    runApplication<IamAuditSvcApplication>(*args)
}
