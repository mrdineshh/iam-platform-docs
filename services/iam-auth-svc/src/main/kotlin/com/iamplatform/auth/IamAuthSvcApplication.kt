package com.iamplatform.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class IamAuthSvcApplication

fun main(args: Array<String>) {
    runApplication<IamAuthSvcApplication>(*args)
}
