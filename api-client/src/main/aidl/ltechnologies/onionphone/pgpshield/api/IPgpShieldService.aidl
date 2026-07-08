package ltechnologies.onionphone.pgpshield.api;

parcelable CallerIdentity;
parcelable EncryptRequestParcel;
parcelable DecryptRequestParcel;
parcelable SignRequestParcel;
parcelable CryptoResultParcel;
parcelable KeySummaryParcel;

interface IPgpShieldService {
    int checkPermission(in CallerIdentity caller);
    CryptoResultParcel encrypt(in EncryptRequestParcel request);
    CryptoResultParcel decrypt(in DecryptRequestParcel request);
    CryptoResultParcel sign(in SignRequestParcel request);
    List<KeySummaryParcel> listKeys(String packageName);
}
