import com.diffplug.gradle.spotless.SpotlessExtension

plugins {
    java
    id("com.gradleup.shadow") version "8.3.9"
    id("com.diffplug.spotless") version "6.25.0"
}

// We need this dependency to load the resource JNA shared libraries
dependencies {
    implementation("net.java.dev.jna:jna:5.18.1")
}

configure<SpotlessExtension> {
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

val copyAgentShadowJar by tasks.registering(Copy::class) {
    dependsOn(":agent:shadowJar")
    from(project(":agent").tasks.named("shadowJar").get().outputs.files)
    into("$projectDir/src/main/resources/agent")
    rename { "agent.zip" }
}

tasks.named("spotlessJava") {
    mustRunAfter(copyAgentShadowJar)
}

tasks.clean {
    doFirst {
        delete(fileTree("$projectDir/src/main/resources/agent"))
    }
}

tasks.processResources {
    dependsOn(copyAgentShadowJar)
}

tasks.shadowJar {
    archiveBaseName.set("loader")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("shaded")
    manifest {
        attributes(
            "Main-Class" to "io.opentelemetry.obi.java.Loader",
            "Premain-Class" to "io.opentelemetry.obi.java.Loader",
            "Agent-Class" to "io.opentelemetry.obi.java.Loader",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true"
        )
    }
}