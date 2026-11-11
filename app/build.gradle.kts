plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

android {
    namespace = "dev.kailashrs.infinitylock"
    compileSdk {
        version = release(37) {
            minorApiLevel = 2
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "dev.kailashrs.infinitylock"
        minSdk = 26
        targetSdk = 37
        versionCode = 3
        versionName = "1.1.0-rc.2"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        buildConfig = true
        aidl = true
        compose = true
    }

    androidResources {
        // Keep payload binaries uncompressed so on-device sha256 staging is byte-exact.
        noCompress += listOf("payload/ic98260", "payload/ksupatch", "payload/insmodf", "payload/ksuquery", "payload/ksu_exposure_probe", "payload/ksud", "payload/kernelsu.ko", "payload/run.sh")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.miuix)
    implementation("top.yukonga.miuix.kmp:miuix-preference:0.9.4")
    implementation("top.yukonga.miuix.kmp:miuix-icons:0.9.4")
    implementation(libs.shizuku.api)
    implementation(libs.shizuku.provider)
}


val verifyPayloads by tasks.registering {
    val payloadDir = layout.projectDirectory.dir("src/main/assets/payload")
    inputs.dir(payloadDir)
    doLast {
        listOf("ic98260", "ksupatch", "insmodf", "ksuquery", "ksu_exposure_probe", "kernelsu.ko", "ksud", "run.sh").forEach { name ->
            val file = payloadDir.file(name).asFile
            check(file.isFile && file.length() > 0) {
                "Missing $name. Run ../build-payload.sh to build the pinned runtime payloads."
            }
        }
    }
}
tasks.named("preBuild").configure { dependsOn(verifyPayloads) }
