# keycloak-hmac-sha
Keycloak Authentication SPI for HMAC SHA hashing.  This is a simple implementation which that takes the raw password from the user concatenates the generated salt value and then hashes it.  This is very much not that secure over newer best practices that utilizes PBKDF2 (Password-Based Key Derivation Function 2) with iterations that provide a heavy compute cost for brute force attacks.

## Build JAR

```bash
./gradlew assemble
```

After compile is successful the jar file will be located at:
```
\build\libs
```

## Keycloak Config

The jar file created by the compile command and located in \build\libs needs to be installed at /opt/keycloak/providers and keycloak rebooted.

These algorithms require a algorithm key to initialize and that can be provided using the startup command of keycloak which follows the following naming scheme:

--spi-password-hashing-{provider id}-{key name}={key value}

Example for HMAC SHA512:
```
start --spi-password-hashing-hmac-sha512-key=StrongAlgorithmSecretKey
```
