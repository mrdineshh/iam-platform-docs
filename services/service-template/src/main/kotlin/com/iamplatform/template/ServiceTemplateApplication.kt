package com.iamplatform.template

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

/**
 * Copy-paste starting point for every service in Section 6's build order.
 * Actuator health endpoints, OpenTelemetry auto-instrumentation, and the
 * correlation-ID filter all come from iam-service-kit's autoconfiguration —
 * nothing to wire here. Each service replaces this file with its own
 * @SpringBootApplication class in its own package and adds its own domain
 * controllers/services/repositories.
 */
@SpringBootApplication
class ServiceTemplateApplication

fun main(args: Array<String>) {
    runApplication<ServiceTemplateApplication>(*args)
}
