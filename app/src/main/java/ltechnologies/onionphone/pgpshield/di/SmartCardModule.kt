package ltechnologies.onionphone.pgpshield.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.engine.CompositeSmartCardPort
import ltechnologies.onionphone.pgpshield.engine.SmartCardPort
import ltechnologies.onionphone.pgpshield.smartcard.OpenPgpCardNfcPort
import ltechnologies.onionphone.pgpshield.smartcard.OpenPgpCardUsbPort

@Module
@InstallIn(SingletonComponent::class)
object SmartCardModule {
    @Provides
    @Singleton
    fun provideSmartCardPort(
        nfc: OpenPgpCardNfcPort,
        usb: OpenPgpCardUsbPort,
    ): SmartCardPort = CompositeSmartCardPort(listOf(nfc, usb))
}
