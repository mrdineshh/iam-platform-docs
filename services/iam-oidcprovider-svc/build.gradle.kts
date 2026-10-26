plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.spring") version "2.3.21"
    id("org.springframework.boot") version "4.1.1"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.iamplatform"
version = "0.1.0"
description = "iam-oidcprovider-svc"

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
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-opentelemetry")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("tools.jackson.module:jackson-module-kotlin")
    implementation("com.nimbusds:nimbus-jose-jwt:9.41.2")
    // SAML IdP support (self-signed signing cert + assertion signing). Not
    // OpenSAML -- that's only published on Shibboleth's own Nexus repo, not
    // Maven Central, which this build deliberately doesn't add (an extra,
    // less-reliable artifact source for a one-off dependency isn't worth
    // it). Bouncy Castle (already used elsewhere in this codebase, e.g.
    // iam-identity-svc's Argon2 provider) generates the self-signed X.509
    // cert; the actual XML signature is built with the JDK's own
    // javax.xml.crypto.dsig (standard since Java 6), not hand-rolled.
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.named<org.springframework.boot.gradle.tasks.run.BootRun>("bootRun") {
    systemProperty("user.timezone", "UTC")
}
