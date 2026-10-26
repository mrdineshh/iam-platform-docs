package com.iamplatform.enforcement

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan
class IamEnforcementSvcApplication

fun main(args: Array<String>) {
    runApplication<IamEnforcementSvcApplication>(*args)
}
