package com.iamplatform.session

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(SessionProperties::class)
class IamSessionSvcApplication

fun main(args: Array<String>) {
    runApplication<IamSessionSvcApplication>(*args)
}
