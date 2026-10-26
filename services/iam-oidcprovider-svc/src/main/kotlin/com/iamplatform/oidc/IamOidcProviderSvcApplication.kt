package com.iamplatform.oidc

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(OidcProperties::class, SamlProperties::class)
class IamOidcProviderSvcApplication

fun main(args: Array<String>) {
    runApplication<IamOidcProviderSvcApplication>(*args)
}
