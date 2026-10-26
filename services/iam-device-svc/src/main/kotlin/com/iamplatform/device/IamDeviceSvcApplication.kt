package com.iamplatform.device

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan
class IamDeviceSvcApplication

fun main(args: Array<String>) {
    runApplication<IamDeviceSvcApplication>(*args)
}
