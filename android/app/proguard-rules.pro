# gomobile: the Go runtime finds these classes and methods by name over JNI.
-keep class go.** { *; }
-keep class mobilebridge.** { *; }
-dontwarn go.**
# HEV tunnel: native code is bound to this exact class and its method names.
-keep class hev.htproxy.** { *; }
# Kotlin implementations of gomobile interfaces are called back from Go.
-keep class * implements mobilebridge.** { *; }
-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod
