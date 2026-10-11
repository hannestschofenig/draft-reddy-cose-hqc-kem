---
title: Hamming Quasi-Cyclic (HQC) Key Encapsulation Mechanisms for COSE
abbrev: HQC KEM for COSE
docname: draft-reddy-cose-hqc-kem-latest
category: std
ipr: trust200902
submissiontype: IETF
v: 3
area: "Security"
workgroup: "CBOR Object Signing and Encryption"
keyword:
- COSE
- HQC
- Post-Quantum Cryptography
- Key Encapsulation Mechanism
author:
- fullname: Hannes Tschofenig
  organization: University of the Bundeswehr Munich
  abbrev: UniBw M.
  city: Neubiberg
  code: '85577'
  country: Germany
  email: hannes.tschofenig@gmx.net
- fullname: Tirumaleswar Reddy
  organization: Nokia
  city: Bangalore
  region: Karnataka
  country: India
  email: kondtir@gmail.com
normative:
  RFC8949:
  RFC9052:
  RFC9053:
  RFC9964:
  PQ-KEM: I-D.ietf-jose-pqc-kem
  COSE-HPKE: I-D.ietf-cose-hpke
  HQC:
    title: "Hamming Quasi-Cyclic (HQC)"
    author:
      - org: HQC Project
    date: 2025-08-22
    target: https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf
informative:
  NIST.IR.8545:
    title: "Status Report on the Fourth Round of the NIST Post-Quantum Cryptography Standardization Process"
    author:
      - org: National Institute of Standards and Technology
    date: 2025-03
    target: https://doi.org/10.6028/NIST.IR.8545
  IANA.cose:
    title: "CBOR Object Signing and Encryption (COSE)"
    author:
      - org: IANA
    target: https://www.iana.org/assignments/cose

--- abstract

This document extends the Post-Quantum Key Encapsulation Mechanisms
(PQ KEMs) for COSE framework with Hamming Quasi-Cyclic (HQC). It defines
HQC recipient algorithms for Direct Key Agreement and Key Agreement
with Key Wrap, and specifies the representation of HQC keys using the
Algorithm Key Pair (AKP) key type. It reuses the framework's key
derivation and encapsulated-key transport and requests six COSE
algorithm registrations.

--- middle

# Introduction

{{PQ-KEM}} defines a framework for using post-quantum key encapsulation
mechanisms with CBOR Object Signing and Encryption (COSE) {{RFC9052}},
and instantiates that framework with ML-KEM. This document adds HQC as
another KEM within that framework.

HQC is code-based, providing a different mathematical foundation from
ML-KEM. NIST selected HQC for standardization following its fourth-round
evaluation {{NIST.IR.8545}}. This document uses the HQC submission
specification {{HQC}}. The publication of this specification will
advance once a final NIST HQC standard becomes available.

The generic processing in Sections 4.2, 4.3, 5, and 6 of {{PQ-KEM}}
applies with the HQC KEM selected by this document. This document
supplies the additional algorithm registrations and HQC key
representation.

The extension defines three Direct Key Agreement algorithms and three
Key Agreement with Key Wrap algorithms. It specifies the HQC inputs to
the existing processing model. This specification focuses on the COSE
functionality and does not define JOSE algorithms.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The terms Direct Key Agreement, Key Agreement with Key Wrap, Content
Encryption Key (CEK), and COSE_Recipient are used as in {{RFC9052}} and
{{PQ-KEM}}. KEK denotes the key-encryption key used to wrap a CEK.

This document uses `pk` for an HQC public encapsulation key, `sk` for
the corresponding private decapsulation key, `CT` for a KEM ciphertext,
and `SS'` for the KEM shared secret. The COSE header parameter `ek`
carries `CT`; it does not carry `pk`. All lengths in octets refer to
raw values before CBOR encoding {{RFC8949}}.

# HQC Algorithms {#hqc-algorithms}

Implementations MUST use HQC-KEM from Section 3.6 of {{HQC}}, with the
parameter sets and byte encodings of that specification. HQC-PKE alone
MUST NOT be used in its place.

| Parameter set | NIST category | Public key | Private seed | Ciphertext | Shared secret |
|:--------------|--------------:|-----------:|-------------:|-----------:|--------------:|
| HQC-1         | 1             | 2241       | 32           | 4433       | 32            |
| HQC-3         | 3             | 4514       | 32           | 8978       | 32            |
| HQC-5         | 5             | 7237       | 32           | 14421      | 32            |
{: #hqc-sizes title="HQC lengths in octets (HQC specification, Section 4)"}

This profile defines only the compressed private seed based on {{HQC}}.

## COSE Algorithm Identifiers {#algorithms}

Each identifier in {{suites}} selects the KEM, KMAC256 key derivation,
and the mode. The key-wrap identifiers also select the AES Key Wrap
algorithm.

| Name | Value | KEM | Mode | Wrap |
|:-----|:------|:----|:-----|:-----|
| HQC-1 | TBD-HQC-1 | HQC-1 | Direct | None |
| HQC-3 | TBD-HQC-3 | HQC-3 | Direct | None |
| HQC-5 | TBD-HQC-5 | HQC-5 | Direct | None |
| HQC-1+A128KW | TBD-HQC-1-KW | HQC-1 | Wrap | A128KW |
| HQC-3+A192KW | TBD-HQC-3-KW | HQC-3 | Wrap | A192KW |
| HQC-5+A256KW | TBD-HQC-5-KW | HQC-5 | Wrap | A256KW |
{: #suites title="HQC COSE recipient algorithms"}

# Using HQC in the PQ-KEM Framework {#processing}

## Encapsulation and Decapsulation

The sender selects an algorithm from {{suites}} and validates the
recipient key as specified in {{keys}}. It invokes HQC-KEM.Encaps with
`pk`, obtaining the named outputs `SS'` and `CT`, and applies the KDF
from Section 5 of {{PQ-KEM}} as profiled in {{kdf}}.

The recipient validates the headers, algorithm/key association, and
ciphertext length before invoking HQC-KEM.Decaps with `sk` and `CT`.
It applies the same KDF to the resulting `SS'`. The algorithm inputs
and outputs are identified by name here because the generic interface
and processing examples in {{PQ-KEM}} use different argument and
return-value orders.

The shared secret MUST NOT be used directly as the CEK or KEK. Both
parties MUST use the complete HQC-KEM operation, including its specified
implicit rejection. They MUST NOT substitute a separate COSE-level
Fujisaki-Okamoto transform. The subsequent KDF serves key derivation
and context binding.

Implicit rejection produces a replacement shared secret and is not an
explicit decapsulation error exposed to the application. Processing
continues through key derivation and the normal unwrap or content
authentication checks. If the KEM operation instead reports an explicit
error, processing MUST stop with a decryption failure, as required by
Section 4.3 of {{PQ-KEM}}.

## Key Derivation {#kdf}

All six algorithms use KMAC256 with the inputs defined by Section 5.1
of {{PQ-KEM}}: the KEM shared secret is `K`, the encoded context is `X`,
the requested output length in bits is `L`, and the customization string
`S` is empty.

The context is the Section 5.2 {{RFC9053}} structure with PartyUInfo
and PartyVInfo omitted, as required by {{PQ-KEM}}. AlgorithmID denotes
the algorithm that consumes the derived key: the content-encryption
algorithm in Direct mode, or A128KW (-3), A192KW (-4), or A256KW (-5)
in Wrap mode. SuppPubInfo.keyDataLength equals `L`.
SuppPubInfo.protected contains the exact recipient protected-header
byte string. Optional context information follows {{PQ-KEM}} and
{{RFC9053}} and MUST be agreed by both parties.

This profile requires the recipient `alg` to be protected so that the
selected HQC algorithm, including its mode, is also bound into the KDF
context. In particular, AlgorithmID alone does not identify the KEM.

In Direct mode, `L` MUST equal the CEK length required by the selected
content-encryption algorithm. This profile requires at least 128,
192, or 256 bits of CEK length for HQC-1, HQC-3, or HQC-5, respectively.
An incompatible content-encryption algorithm MUST be rejected. The
KDF output MUST NOT be truncated to bypass this requirement.

In Wrap mode, `L` is 128, 192, or 256 bits for HQC-1+A128KW,
HQC-3+A192KW, or HQC-5+A256KW, respectively. This is the KEK length,
not the length of the independently generated CEK. The content
algorithm determines the CEK length. These length requirements do not
by themselves establish the security strength of the complete message.

## Headers and Ciphertext Transport {#headers}

Both modes use COSE_Encrypt with COSE_Recipient structures as described
in Section 6 of {{PQ-KEM}}. The outer `alg` identifies the content
encryption algorithm. The recipient `alg` identifies an algorithm from
{{suites}}. The recipient `alg` MUST be in the protected header.

The sender MUST place the complete `CT` byte string in the recipient
`ek` header parameter reused by {{PQ-KEM}} from {{COSE-HPKE}}.

The `ek` MUST be in the recipient unprotected header. This
placement avoids including the large ciphertext in the KDF context;
its cryptographic processing is performed by HQC decapsulation.

The recipient MUST reject a missing `ek`, a non-byte-string value, or
a length different from {{hqc-sizes}} for the selected KEM. Normal
COSE checks for duplicate and conflicting header parameters also apply.
The sender SHOULD include a recipient `kid` to identify the intended
key. A `kid` is a lookup hint, not proof of key authenticity.

The numeric label of the `ek` header parameter is defined by {{COSE-HPKE}}.

## Direct Key Agreement

The KDF output is the CEK used for the COSE_Encrypt content. The
recipient ciphertext field MUST be CBOR `null`. This profile uses
exactly one recipient in Direct mode. Applications needing multiple
recipients use Wrap mode. A fresh encapsulation MUST be performed for
each new encrypted message.

Detached content uses `null` in the outer ciphertext field, with the
encrypted content conveyed separately according to {{RFC9052}}. That
outer field is distinct from the recipient ciphertext field.

## Key Agreement with Key Wrap

The sender generates a fresh CEK suitable for the content algorithm
and encrypts the content once. For each recipient, it performs an
independent encapsulation, derives that recipient's KEK, and wraps the
CEK with the AES Key Wrap algorithm selected by {{suites}}. The wrapped
CEK is placed in the recipient ciphertext field as a byte string.

The recipient decapsulates `ek`, derives the KEK, unwraps the CEK, and
then authenticates and decrypts the content. It MUST NOT release
plaintext when unwrapping or content authentication fails. Other
recipient algorithms may be present if permitted by the application;
the security consequences are discussed in {{security}}.

# HQC COSE Keys {#keys}

HQC keys use AKP as defined in {{RFC9964}}, following Section 8 of
{{PQ-KEM}}. The required `kty` (label 1) is 7; `alg` (label 3) is one
of the integer identifiers in {{suites}}; and `pub` (label -1) is the
raw public-key byte string. A private key additionally includes `priv`
(label -2).

For HQC, `priv` MUST contain exactly the 32-octet `seedKEM` compressed
representation defined by {{HQC}}. The key pair is recovered by the
specified key-generation procedure using that seed. An implementation
MUST NOT reinterpret the HQC private key as a seed or private
key of another algorithm. When importing a private key, the implementation
MUST regenerate the public key and reject a mismatch with `pub`.

Before using a key, implementations MUST verify `kty`, the selected
`alg`, the required byte-string types and lengths, and any applicable
key-use restrictions. They MUST apply the checks required by {{HQC}}.
Unknown algorithm identifiers and inconsistent key representations
MUST be rejected.

Each COSE_Key MUST bind to one recipient algorithm. An HQC-1 key
object therefore cannot be used as an HQC-1+A128KW key object.
Applications MUST NOT silently relabel a key to bypass this
restriction. Provisioning separate key pairs for different
recipient algorithms is strongly RECOMMENDED.

If `key_ops` is present, it MUST permit key derivation (`deriveKey`,
value 7). It MUST NOT be interpreted as permission to sign or to use
the HQC private key directly as a symmetric decryption key.

No `crv` parameter is used. AKP thumbprints follow Section 6 of
{{RFC9964}}. Because `alg` is included, changing the algorithm binding
also changes the thumbprint even if the public-key bytes are unchanged.

# Security Considerations {#security}

The security considerations of {{PQ-KEM}}, {{RFC9052}}, {{RFC9053}},
and {{HQC}} apply. This extension specifies a COSE integration and
does not provide a security proof for HQC.

Implementations MUST obtain key-generation and encapsulation randomness
from a cryptographically secure random number generator. Private seeds,
expanded private keys, shared secrets, and derived keys MUST be
protected against disclosure, including through logs and diagnostic
interfaces. Intermediate KEM values MUST NOT be used as COSE keying
material or exposed as application data.

Implementations MUST preserve implicit rejection and avoid externally
distinguishable secret-dependent error behavior. They SHOULD use
constant-time implementations for secret-dependent computations.
Malformed public inputs can be rejected before decapsulation, but
failure handling MUST NOT disclose whether an internal ciphertext
consistency test succeeded. A failed unwrap or content authentication
MUST produce a decryption failure without releasing plaintext.

Encapsulation does not authenticate the sender: anyone possessing a
recipient public key can generate an encapsulation. Applications
requiring sender authentication need to embed HQC into a KEM-based
authentication protocol or need to apply a signature mechanism.
Public-key distribution MUST provide the
recipient-key authenticity required by the application. Possession of
a `kid` alone does not provide it.

Use of a long-lived recipient key does not provide forward secrecy
against later compromise of its private key. Recorded ciphertexts can
then be decapsulated. Applications must choose key lifetimes and key
deletion policies accordingly.

This profile permits that public-key reuse subject to the KEM and
application usage limits, but requires fresh encapsulation randomness
for every new message and every independently encapsulated recipient.

Algorithm selection MUST be constrained by application policy. For
multiple recipients, confidentiality depends on every method that can
recover the CEK. Adding a traditional recipient to the same message
does not create a post-quantum/traditional hybrid KEM.

Content encryption, key wrapping, and key derivation can limit overall
security even when a higher-category KEM is selected. Nonce uniqueness
and per-key usage limits of the content algorithm still apply. The
large HQC ciphertexts also require bounded parsing, memory allocation,
and decapsulation workloads to mitigate denial of service. Each
additional recipient increases message size and processing cost.
Applications SHOULD assess the complete encoded COSE message against
transport, storage, and reassembly limits, including per-recipient
ciphertexts and wrapped keys.

Supporting HQC alongside ML-KEM provides algorithm choice based on
different mathematical assumptions. Selecting one of the standalone
HQC algorithms in this document does not obtain the combined security
of the PQ/PQ or PQ/T hybrids. In particular, placing independently
wrapped copies of a CEK in HQC and ML-KEM recipients allows either
private key to recover that CEK. it does not require an attacker to
defeat both KEMs. A claim of security when one component fails
requires a suitably specified and analyzed hybrid construction,
including its implementation assumptions.

# IANA Considerations {#iana}

IANA is requested to register the six entries below in the "COSE
Algorithms" registry {{IANA.cose}}. Each row supplies Name, Value, and
Description. All entries have Capabilities `[kty]`, Change Controller
`IESG`, Reference "this document, {{hqc-algorithms}} and {{processing}}",
and Recommended `No`, following the registration approach of {{PQ-KEM}}.

| Name | Value | Description |
|:-----|:------|:------------|
| HQC-1 | TBD-HQC-1 | HQC-1 with KMAC256, Direct Key Agreement |
| HQC-3 | TBD-HQC-3 | HQC-3 with KMAC256, Direct Key Agreement |
| HQC-5 | TBD-HQC-5 | HQC-5 with KMAC256, Direct Key Agreement |
| HQC-1+A128KW | TBD-HQC-1-KW | HQC-1 with KMAC256 and A128KW |
| HQC-3+A192KW | TBD-HQC-3-KW | HQC-3 with KMAC256 and A192KW |
| HQC-5+A256KW | TBD-HQC-5-KW | HQC-5 with KMAC256 and A256KW |

HQC parameter selection is carried by `alg` in an AKP key. No new key
type, key parameter, header parameter, or JOSE registration is requested.

--- back

# Examples {#examples}

The following pseudocode illustrates field placement. `bstr(...)`
means the byte-string value supplied by the named operation;
`encode(...)` means CBOR encoding. Symbolic algorithm and header
identifiers stand for integer assignments. These are not CBOR diagnostic
notation, executable examples, or cryptographic test vectors.

A future version of this specification will provide working
examples.

## Public and Private Keys

An HQC-1 Direct-mode public key is:

~~~
{
  1: 7,                         / kty: AKP /
  3: TBD-HQC-1,                 / alg /
 -1: bstr(public_key)           / 2241 octets /
}
~~~

The corresponding private key adds `-2: bstr(seedKEM)` (32 octets).

## Direct Mode with A128GCM

~~~
96([
  encode({1: 1}),               / outer alg: A128GCM /
  {5: bstr(iv)},                / 12-octet IV /
  bstr(encrypted_content),      / includes authentication tag /
  [
    [
      encode({1: TBD-HQC-1}),   / recipient protected /
      {
        4: bstr(recipient_kid),
       -4: bstr(CT)            / 4433-octet HQC ciphertext /
      },
      null                     / no wrapped CEK /
    ]
  ]
])
~~~

Here `SS'` is processed with KMAC256 to derive a 128-bit CEK.
AlgorithmID in the KDF context is 1 (A128GCM).

## Wrap Mode with A256GCM

~~~
96([
  encode({1: 3}),               / outer alg: A256GCM /
  {5: bstr(iv)},                / 12-octet IV /
  bstr(encrypted_content),
  [
    [
      encode({1: TBD-HQC-5-KW}),
      {
        4: bstr(recipient_kid),
       -4: bstr(CT)      / 14421-octet HQC ciphertext /
      },
      bstr(wrapped_cek)         / 40 octets for a 32-octet CEK /
    ]
  ]
])
~~~

Here the sender independently generates a 256-bit CEK. KMAC256 derives
a 256-bit KEK, and A256KW wraps the CEK. AlgorithmID in the KDF context
is -5 (A256KW). Additional recipients have independent encapsulations
and wrapped copies of the same CEK.
