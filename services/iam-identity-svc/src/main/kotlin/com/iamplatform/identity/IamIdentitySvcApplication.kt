package com.iamplatform.identity

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class IamIdentitySvcApplication

fun main(args: Array<String>) {
    runApplication<IamIdentitySvcApplication>(*args)
}
