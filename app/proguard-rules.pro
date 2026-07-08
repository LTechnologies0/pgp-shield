-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

-keep @androidx.room.Entity class *
-keepclassmembers class * {
    @androidx.room.* <methods>;
}

-keep @dagger.hilt.android.lifecycle.HiltViewModel class * { *; }

-keep class ltechnologies.onionphone.pgpshield.api.** { *; }
-keep class org.openintents.openpgp.** { *; }
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-keep class ltechnologies.onionphone.pgpshield.api.IPgpShieldService$Stub$Proxy { *; }
