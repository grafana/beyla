plugins {
    java
    id("com.gradleup.shadow") version "8.3.9"
    id("me.champeau.jmh") version "0.7.3"
    id("com.diffplug.spotless") version "8.2.0"
}

group = "io.opentelemetry.obi"
version = "0.1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
        // Use Google Java Format
        googleJavaFormat()
        // Or use Eclipse formatter
        // eclipse()

        // Remove unused imports
        removeUnusedImports()

        // Trim trailing whitespace
        trimTrailingWhitespace()

        // End files with newline
        endWithNewline()

        // Target files
        target("src/**/*.java")
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.bytebuddy:byte-buddy:1.18.4")
    implementation("net.bytebuddy:byte-buddy-agent:1.17.8")
    implementation("net.java.dev.jna:jna:5.18.1")
    implementation("com.github.ben-manes.caffeine:caffeine:2.9.3")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.13.3")
    testImplementation("org.junit.platform:junit-platform-launcher:1.10.2")
    testImplementation("org.awaitility:awaitility:4.3.0")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.13.3")
}

tasks.test {
    useJUnitPlatform()
}

val jmhIncludes: String? by project
val jmhProfilers: String? by project

jmh {
    includes.set(listOf(".*Benchmark.*"))
    jmhIncludes?.let {
        includes.set(listOf(it))
    }
    jmhProfilers?.let { profilersStr ->
        profilers.set(profilersStr.split(",").map { p: String -> p.trim() })
    }
    benchmarkMode.set(listOf("avgt"))
    timeUnit.set("ns")
    warmupIterations.set(3)
    iterations.set(5)
    fork.set(1)
    jvmArgs.set(listOf("-Xmx2G"))
}

tasks.shadowJar {
    archiveBaseName.set("agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("shaded")
    manifest {
        attributes(
            "Premain-Class" to "io.opentelemetry.obi.java.Agent",
            "Agent-Class" to "io.opentelemetry.obi.java.Agent",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Main-Class" to "io.opentelemetry.obi.java.Agent"
        )
    }
    relocate("com.github", "io.opentelemetry.obi.com.github")
    relocate("net.bytebuddy", "io.opentelemetry.obi.net.bytebuddy")
    // Exclude META-INF files as in Maven Shade plugin
    exclude("META-INF/**")
    exclude("META-INF/versions/9/module-info.class")
}