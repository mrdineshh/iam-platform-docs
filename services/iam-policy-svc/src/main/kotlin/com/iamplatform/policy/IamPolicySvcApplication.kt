package com.iamplatform.policy

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class IamPolicySvcApplication

fun main(args: Array<String>) {
    runApplication<IamPolicySvcApplication>(*args)
}
