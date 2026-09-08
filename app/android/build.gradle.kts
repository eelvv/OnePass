allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

// Pin every plugin module to the app's compileSdk (36). Several vendored
// plugins hardcode older values (file_picker 8.x = 34, share_plus 10.x = 34),
// which fails their own CheckAarMetadata when a dependency requires 36+.
// Raising compileSdk is safe for libraries; targetSdk/minSdk stay theirs.
//
// NOTE: registered BEFORE `evaluationDependsOn(":app")` below — that call
// forces :app to evaluate immediately, and afterEvaluate cannot be added to
// an already-evaluated project.
subprojects {
    afterEvaluate {
        if (plugins.hasPlugin("com.android.library")) {
            extensions.configure<com.android.build.gradle.LibraryExtension>("android") {
                compileSdk = 36
            }
        }
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
