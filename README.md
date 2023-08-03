# keycloak-hmac-sha
Keycloak Authentication SPI for HMAC SHA hashing.  This is a simple implementation which that takes the raw password from the user concatenates the generated salt value and then hashes it.  This is very much not that secure over newer best practices that utilizes PBKDF2 (Password-Based Key Derivation Function 2) with iterations that provide a heavy compute cost for brute force attacks.  This plugin by default will re-hash passwords that successfully validate in order to slowly migrate legacy passwords to newer practices.

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

# Acknowledgements

It is worth pointing out that this plugin is heavily based on another example found in GitHub and worth checking out that repository as well.  This code is purpose built to solve a problem with migrating thousands of users from a legacy system that used HMAC SHA512 and be able to continue using those existing password hashes.  There is likely files in this repository that are forked from the below repo and may not be used in this implementation especially around Docker files.

Please check out the BCrypt example here:
https://github.com/leroyguillaume/keycloak-bcrypt

