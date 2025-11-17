pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.namespace == "com.android" 
                || requested.id.name == "kotlin-android-extensions") 
            {
                useModule("com.android.tools.build:gradle:8.9.0")
            }
        }
    }
}

rootProject.name = "libsodium-kmp"

val skipAndroid = File("$rootDir/local.properties").takeIf { it.exists() }
    ?.inputStream()?.use { java.util.Properties().apply { load(it) } }
    ?.run { getProperty("skip.android", "false")?.toBoolean() }
    ?: false

System.setProperty("includeAndroid", (!skipAndroid).toString())

include(
    ":jni",
    ":native"
)

if (!skipAndroid) {
    print("building android library")
    include(":jni:android")
} else {
    print("skipping android build")
}