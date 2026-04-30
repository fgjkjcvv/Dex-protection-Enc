.class public Lcom/secure/Decryptor;
.super Ljava/lang/Object;

.field private static final key:[B

.method static constructor <clinit>()V
    .registers 1
    const-string v0, "MySecureKey12345"
    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
    move-result-object v0
    sput-object v0, Lcom/secure/Decryptor;->key:[B
    return-void
.end method

.method public static decrypt(Ljava/lang/String;)Ljava/lang/String;
    .registers 5
    :try_start
    invoke-static {p0}, Lcom/secure/Decryptor;->base64Decode(Ljava/lang/String;)[B
    move-result-object v0
    sget-object v1, Lcom/secure/Decryptor;->key:[B
    invoke-static {v0, v1}, Lcom/secure/Decryptor;->aesDecrypt([B[B)Ljava/lang/String;
    move-result-object v0
    return-object v0
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_0
    :catch_0
    return-object p0
.end method

.method private static base64Decode(Ljava/lang/String;)[B
    .registers 2
    const/4 v0, 0x0
    invoke-static {p0, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
    move-result-object v0
    return-object v0
.end method

.method private static aesDecrypt([B[B)Ljava/lang/String;
    .registers 5
    new-instance v0, Ljavax/crypto/spec/SecretKeySpec;
    const-string v1, "AES"
    invoke-direct {v0, p1, v1}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    const-string v1, "AES/ECB/PKCS5Padding"
    invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v1
    const/4 v2, 0x2
    invoke-virtual {v1, v2, v0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V
    invoke-virtual {v1, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B
    move-result-object v0
    new-instance v1, Ljava/lang/String;
    invoke-direct {v1, v0}, Ljava/lang/String;-><init>([B)V
    return-object v1
.end method