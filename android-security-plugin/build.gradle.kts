import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.intellij.platform.gradle.extensions.intellijPlatform
import org.jetbrains.intellij.platform.gradle.tasks.RunIdeTask
import java.io.FileInputStream
import java.util.Properties

plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "2.3.20"
    id("org.jetbrains.intellij.platform") version "2.16.0"
}

group = "com.hkkkkjv"
version = "1.0-SNAPSHOT"

intellijPlatform {
    pluginConfiguration {
        name = "Network Security Analyzer"
        id = "com.hkkkkjv.androidsecurityplagin"
    }
}
repositories {
    mavenCentral()
    maven {
        url = uri("https://repo1.maven.org/maven2")
    }
    intellijPlatform {
        defaultRepositories()
    }
}

// Configure Gradle IntelliJ Plugin
// Read more: https://plugins.jetbrains.com/docs/intellij/tools-gradle-intellij-plugin.html
dependencies {
    intellijPlatform {
        local("/Applications/Android Studio.app/Contents")
        bundledPlugins(
            "org.jetbrains.kotlin",
            "com.intellij.gradle",
            "org.jetbrains.android",
            "org.intellij.groovy",
            "com.intellij.java",

        )
        testFramework(TestFrameworkType.Platform)
    }
    implementation("com.google.code.gson:gson:2.14.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation("junit:junit:4.13.2")
}
intellijPlatformTesting {
    runIde {
    }
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(FileInputStream(localPropertiesFile))
}
tasks {
    withType<JavaCompile> {
        sourceCompatibility = "17"
        targetCompatibility = "17"
    }
    withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }
    named<RunIdeTask>("runIde") {
        val analyzerPath = localProperties.getProperty("analyzer.path")

        if (analyzerPath != null) {
            environment("ANDROID_SEC_ANALYZER_PATH" to analyzerPath)
        } else {
            // Опционально: предупреждение, если путь не настроен
        }
    }
}
