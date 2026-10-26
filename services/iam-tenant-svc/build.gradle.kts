plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.spring") version "2.3.21"
    id("org.springframework.boot") version "4.1.1"
    id("io.spring.dependency-management") version "1.1.7"
    kotlin("plugin.jpa") version "2.3.21"
}

group = "com.iamplatform"
version = "0.1.0"
description = "iam-tenant-svc"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.iamplatform:iam-service-kit")

    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-flyway")
    implementation("org.springframework.boot:spring-boot-starter-kafka")
    implementation("org.springframework.boot:spring-boot-starter-opentelemetry")
    // Added for Service 14 (iam-admin-console) -- first outbound HTTP calls
    // this service makes (session-svc/identity-svc for the new admin-check
    // guard). Spring Boot 4 requires this module for outbound-call tracing
    // to work at all (found in Service 7, docs/DECISIONS.md).
    implementation("org.springframework.boot:spring-boot-starter-restclient")
    implementation("org.flywaydb:flyway-database-postgresql")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("tools.jackson.module:jackson-module-kotlin")
    implementation("org.springframework.security:spring-security-crypto")
    // Argon2PasswordEncoder needs BouncyCastle at runtime -- spring-security-crypto
    // declares it optional (same fix as iam-identity-svc, Service 7).
    runtimeOnly("org.bouncycastle:bcprov-jdk18on:1.79")
    runtimeOnly("org.postgresql:postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.boot:spring-boot-starter-data-jpa-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

allOpen {
    annotation("jakarta.persistence.Entity")
    annotation("jakarta.persistence.MappedSuperclass")
    annotation("jakarta.persistence.Embeddable")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.named<org.springframework.boot.gradle.tasks.run.BootRun>("bootRun") {
    // Some host OS timezone IDs (e.g. the deprecated "Asia/Calcutta" alias)
    // aren't recognized by the Postgres server as a session TimeZone value,
    // which fails the JDBC connection outright before any query runs.
    systemProperty("user.timezone", "UTC")
}
