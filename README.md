<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: ad-cs-cert-templates

This role deploys a certificate template on an Active Directory Certificate Services (AD CS) Certification Authority (CA).

## Requirements

| Platform | Versions                   |
| -------- | -------------------------- |
| Windows  | `2016` or `2019` or `2022` |

## Dependencies

| Collections       |
| ----------------- |
| ansible.windows   |
| community.windows |

## Role Arguments

Available variables are listed below, along with default values (see defaults/main.yml). Due to the complexity of the values, it's best to create a certificate template from scratch once and look at the values either using Powershell and the `Get-ADObject` CMDlet or Ansible using the `ad.object_info` module.

As the values are highly specific to the environment and use case, the default template is an unattended Web Server TLS certificate.

---

The full LDAP path of the domain where the CA is located.

```yaml
cert_template_domain_path: ""
```

Name of the Certificate Autority (CA).

```yaml
cert_template_ca_name: ""
```

The name of the certificate template.

```yaml
cert_template_name: ""
```

The [msPKI-Minimal-Key-Size](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/58943ff1-024f-46f3-8a6f-baae06de8351) attribute specifies the minimum size in bits of the public key that the client creates to obtain a certificate based on this template.

```yaml
cert_template_key_size: # integer
```

The [msPKI-Private-Key-Flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667) attribute Specifies the private key flags. Its value can be 0, or it can consist of a bitwise OR of flags from the table in the resource + a bitwise AND with the two values below.

```yaml
cert_template_pkey_flag: # integer

# Example: 101056528 (Hex: 0x06060010)

# 0x00000001 - 00000000000000000000000000000001 - 1 - CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL
# ----------------------------------------------------------
# 0x00000020 - 00000000000000000000000000100000 - 32 - CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED
# 0x00000040 - 00000000000000000000000001000000 - 64 - CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM
# ----------------------------------------------------------
# 0x00000010 - 00000000000000000000000000010000 - 16 - CT_FLAG_EXPORTABLE_KEY
# 0x00000080 - 00000000000000000000000010000000 - 128 - CT_FLAG_REQUIRE_SAME_KEY_RENEWAL
# 0x00000100 - 00000000000000000000000100000000 - 256 - CT_FLAG_USE_LEGACY_PROVIDER
# 0x00000000 - 00000000000000000000000000000000 - 0 - CT_FLAG_ATTEST_NONE
# 0x00001000 - 00000000000000000001000000000000 - 4096 - CT_FLAG_ATTEST_PREFERRED
# 0x00002000 - 00000000000000000010000000000000 - 8192 - CT_FLAG_ATTEST_REQUIRED
# 0x00004000 - 00000000000000000100000000000000 - 16384 - CT_FLAG_ATTESTATION_WITHOUT_POLICY
# 0x00000200 - 00000000000000000000001000000000 - 512 - CT_FLAG_EK_TRUST_ON_USE
# 0x00000400 - 00000000000000000000010000000000 - 1024 - CT_FLAG_EK_VALIDATE_CERT
# 0x00000800 - 00000000000000000000100000000000 - 2048 - CT_FLAG_EK_VALIDATE_KEY
# 0x00200000 - 00000000001000000000000000000000 - 2097152 - CT_FLAG_HELLO_LOGON_KEY

# ----------------------------------------------------------
# AND with result of binary OR
# ----------------------------------------------------------
# 0x000F0000 - 00000000000011110000000000000000 - 983040 - determines whether the current CA can issue a certificate based on this template
# 0x0F000000 - 00001111000000000000000000000000 - 251658240 - determines whether the current template is supported by the client


# Webserver Template - Vanilla
# "msPKI-Private-Key-Flag": 16842752,  (Webserver cloned)
# "msPKI-Private-Key-Flag": 17170432, Vanilla (CA - 2016, Client - XP)
# "msPKI-Private-Key-Flag": 101056512, Vanilla (CA - 2016, Client - Win10)
# "msPKI-Private-Key-Flag": 101056512, Vanilla (2016,W10, Publish)
# "msPKI-Private-Key-Flag": 101056528, Vanilla (2016,W10, Publish, Export Pkey)

# Webserver Template - (CA - 2016, Client - Win10)
# msPKI-Private-Key-Flag: 101056768
# msPKI-Private-Key-Flag: 101056768 (Publish)
# msPKI-Private-Key-Flag: 101056784 (Publish, Pkey)
# msPKI-Private-Key-Flag: 101056528 (Publish, Pkey, Key Storage Provider RSA)
# msPKI-Private-Key-Flag: 101056528 (Publish, Pkey, Key Storage Provider RSA, SHA1)
# msPKI-Private-Key-Flag: 101056528 (Publish, Pkey, Key Storage Provider RSA, Must use)
# msPKI-Private-Key-Flag: 101056528 (Publish, Pkey, Key Storage Provider RSA, Must use, SHA256)
```

The [msPKI-RA-Application-Policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/3fe798de-6252-4350-aace-f418603ddeda) attribute encapsulates embedded properties for multipurpose use. The syntax for the data that is stored in this attribute is different, depending on the schema version for the template.

```yaml
cert_template_ra_application_policies: ""
# Example:
# msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`
```

The [msPKI-Certificate-Application-Policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/44012f2d-5ef3-440d-a61b-b30d3d978130) attribute contains multistring attributes that specify a set of application policy OIDs.

```yaml
cert_template_application_policies: ""
# eg. "1.3.6.1.5.5.7.3.1" # (TLS_WEB_SERVER_AUTHENTICATION)
```

The [msPKI-Template-Schema-Version](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/bf5bd40c-0d4d-44bd-870e-8a6bdea3ca88) attribute specifies the schema version of the templates. The allowed values are `1`, `2`, `3`, and `4`. On the latest AD compatibility modes, usually `4`is used.

```yaml
cert_template_schema_version: # integer
```

The [msPKI-Enrollment-Flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1) attribute specifies the enrollment flags. The attribute value can be 0, or it can consist of a bitwise OR of flags from the following table.

```yaml
cert_template_enrollment_flag: # integer
```

The [msPKI-RA-Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1) attribute specifies the number of recovery agent signatures that are required on a request that references this template.

```yaml
cert_template_ra_signature: # integer

# 0x00000001 - CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
# 0x00000002 - CT_FLAG_PEND_ALL_REQUESTS
# 0x00000004 - CT_FLAG_PUBLISH_TO_KRA_CONTAINER
# 0x00000008 - CT_FLAG_PUBLISH_TO_DS
# 0x00000010 - CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
# 0x00000020 - CT_FLAG_AUTO_ENROLLMENT
# 0x00000040 - CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT
# 0x00000100 - CT_FLAG_USER_INTERACTION_REQUIRED
# 0x00000400 - CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE
# 0x00000800 - CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF
# 0x00001000 - CT_FLAG_ADD_OCSP_NOCHECK
# 0x00002000 - CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL
# 0x00004000 - CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS
# 0x00008000 - CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS
# 0x00010000 - CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT
# 0x00020000 - CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST
# 0x00040000 - CT_FLAG_SKIP_AUTO_RENEWAL
# 0x00080000 - CT_FLAG_NO_SECURITY_EXTENSION
```

The [revision](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/5132861c-6f76-4345-9736-484edbae2653) attribute is the major version of the template.

```yaml
cert_template_major_revision: # integer
```

The [msPKI-Template-Minor-Revision](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/3c315531-7cb0-44de-afb9-5c6f9a8aea49) attribute specifies the minor version of the templates.

```yaml
# TODO: Implement handler to increment upon change
cert_template_minor_revision: # integer
```

The [flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/6cc7eb79-3e84-477a-b398-b0ff2b68a6c0) attribute is the general-enrollment flags attribute. These flags are communicated as an integer value of this attribute. The attribute value can be `0`, or it can consist of a bitwise **OR** of flags from the following table.

```yaml
cert_template_flags: # integer

# 0x00000020 - CT_FLAG_AUTO_ENROLLMENT
# 0x00000040 - CT_FLAG_MACHINE_TYPE
# 0x00000080 - CT_FLAG_IS_CA
# 0x00000200 - CT_FLAG_ADD_TEMPLATE_NAME
# 0x00000800 - CT_FLAG_IS_CROSS_CA
# 0x00010000 - CT_FLAG_IS_DEFAULT
# 0x00020000 - CT_FLAG_IS_MODIFIED
# 0x00001000 - CT_FLAG_DONOTPERSISTINDB
# 0x00000002 - CT_FLAG_ADD_EMAIL
# 0x00000008 - CT_FLAG_PUBLISH_TO_DS
# 0x00000010 - CT_FLAG_EXPORTABLE_KEY
```

The following table shows the values that are allowed for the [pKIDefaultKeySpec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ee5d75a7-8416-4a92-b708-ee8f6e8baffb) attribute.

```yaml
cert_template_key_spec: # integer

# 1 - AT_KEYEXCHANGE – Keys used to encrypt/decrypt session keys.
# 2 - AT_SIGNATURE – Keys used to create and verify digital signatures.
```

The [pKIMaxIssuingDepth](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/426ca26e-cdc6-4b6c-95f5-3932edf48a12) attribute is the maximum depth value for the Basic Constraint extension, as specified in `[RFC3280]` section 4.2.1.10.

```yaml
cert_template_issuing_depth: # integer
```

The [pKICriticalExtensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/25f31e8a-879e-4a97-8c16-8512dc5d4e43) attribute is a list of OIDs that identify extensions that MUST have critical flags enabled, if present, in an issued certificate. For more information about critical extensions, see `[RFC3280]` section 4.2.

```yaml
cert_template_crit_extensions: ""
# "2.5.29.15" - Key Usage
```

The [pKIDefaultCSPs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ab04c569-62b5-4904-8624-01d049860e99) attribute is a list of cryptographic service providers (CSPs) that are used to create the private key and public key.

Each list element MUST be in the following format:

intNum, strCSP

where `intNum` is an integer that specifies the priority order in which the system administrator wants the client to use the CSPs listed, and `strCSP` is the CSP name.

```yaml
cert_template_default_csp: ""
# 1,Microsoft Software Key Storage Provider
```

The [pKIExtendedKeyUsage](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/be8af2e6-01d8-49a5-bacf-be641041ac73) attribute is a list of OIDs that represent extended key usages, as specified in `[RFC3280]` section 4.2.1.13.

```yaml
cert_template_ext_key_usage: ""
# "1.3.6.1.5.5.7.3.1" (TLS_WEB_SERVER_AUTHENTICATION)
```

The [msPKI-Certificate-Name-Flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1) attribute specifies the subject name flags. Its value can be `0`, or it can consist of a bitwise **OR** of flags from the following table.

```yaml
cert_template_name_flag: # integer

# CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT - 0x00010000
# CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME - 0x00400000
# CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS - 0x00800000
# CT_FLAG_SUBJECT_ALT_REQUIRE_SPN - 0x01000000
# CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID - 0x02000000
# CT_FLAG_SUBJECT_ALT_REQUIRE_UPN - 0x04000000
# CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL - 0x08000000
# CT_FLAG_SUBJECT_ALT_REQUIRE_DNS - 0x10000000
# CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN - 0x20000000
# CT_FLAG_SUBJECT_REQUIRE_EMAIL - 0x40000000
# CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME - 0x80000000
# CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH - 0x00000008
# CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME
```

The [pKIKeyUsage](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/581a98d5-191c-41e6-b6b9-951f51bb7bdf) attribute is a key usage extension.

```yaml
cert_template_key_usage: # ByteArray generated from list
# Example:
    # - 160
    # - 0
    # -> Digital signature
```

The [pKIExpirationPeriod](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/0adeac05-95df-4730-9871-cf8c27388474) attribute represents the maximum validity period of the certificate. The attribute is an 8-byte octet string that initializes the `FILETIME` structure defined in `[MS-DTYP]` section 2.3.3.

```yaml
cert_template_expiration_period: # ByteArray generated from list
# Example:
    # years: 2
    # months: 0
    # weeks: 0
    # days: 0
    # hours: 0
```

The [pKIOverlapPeriod](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/63c334a0-7a0c-49c5-a95c-c6daa8410a7d) attribute represents the time before a certificate expires, during which time, clients need to send a certificate renewal request, as described in `[MS-CERSOD]` sections 2.5.2, 2.5.3.1, and 3.6. The attribute is an 8-byte octet string that initializes the `FILETIME` structure that is defined in `[MS-DTYP]` section 2.3.3.

```yaml
cert_template_renewal_period: # ByteArray generated from dict
    # years: 0
    # months: 0
    # weeks: 6
    # days: 0
    # hours: 0
```

## Derived Variables / Values

LDAP path to the Public Key Services container.

```yaml
cert_template_pki_root: "CN=Public Key Services,CN=Services,CN=Configuration,{{ cert_template_domain_path }}"
```
