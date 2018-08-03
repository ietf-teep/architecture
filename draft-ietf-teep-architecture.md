---
title: Trusted Execution Environment Provisioning (TEEP) Architecture
abbrev: TEEP Architecture
docname: draft-ietf-teep-architecture-latest
category: info

ipr: pre5378Trust200902
area: Security
workgroup: TEEP
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
author:
 -
       ins: M. Pei
       name: Mingliang Pei
       organization: Symantec
       email: mingliang_pei@symantec.com

 -
       ins: H. Tschofenig
       name: Hannes Tschofenig
       organization: Arm Limited
       email: hannes.tschofenig@arm.com

 -
       ins: D. Wheeler
       name: David Wheeler
       organization: Intel
       email: david.m.wheeler@intel.com

 -
       ins: A. Atyeo
       name: Andrew Atyeo
       organization: Intercede
       email: andrew.atyeo@intercede.com

 -
       ins: L. Dapeng
       name: Liu Dapeng
       organization: Alibaba Group
       email: maxpassion@gmail.com

normative:
  RFC2119:
  RFC8174: 
informative:
  I-D.ietf-teep-opentrustprotocol:
  GPTEE:
    author:
      org: Global Platform
    title: "GlobalPlatform Device Technology: TEE System Architecture, v1.1" 
    date: 2017-01
    target: https://globalplatform.org/specs-library/tee-system-architecture-v1-1/
    seriesinfo:
      Global Platform: GPD_SPE_009

--- abstract

A Trusted Execution Environment (TEE) is designed to provide a 
hardware-isolation mechanism to separate a regular operating system 
from security-sensitive applications.

This architecture document motivates the design and standardization 
of a protocol for managing the lifecyle of trusted applications 
running inside a TEE.

--- middle


#  Introduction

RFC EDITOR: PLEASE REMOVE THE FOLLOWING PARAGRAPH

The source for this draft is maintained in GitHub. Suggested changes
should be submitted as pull requests at 
https://github.com/teep/teep-architecture-spec. Instructions are on that 
page as well. Editorial changes can be managed in GitHub, but any 
substantive change should be discussed on the TEEP mailing list.

Applications executing in a device are exposed to many different attacks 
intended to compromise the execution of the application, or reveal the
data upon which those applications are operating. These attacks increase
with the number of other applications on the device, with such other
applications coming from potentially untrustworthy sources. The 
potential for attacks further increase with the complexity of features
and applications on devices, and the unintented interactions among those
features and applications. The danger of attacks on a system increases 
as the sensitivity of the applications or data on the device increases.
As an example, exposure of emails from a mail client is likely to be of 
concern to its owner, but a compromise of a banking application raises 
even greater concerns.

The Trusted Execution Environment (TEE) concept is designed to execute
applications in a protected environment that separates applications
inside the TEE from the regular operating system and from other 
applications on the device. This separation reduces the possibility
of a successful attack on applications and the data contained inside the
TEE. Typically, applications are chosen to execute inside a TEE because
those applications perform security sensitive operations or operate on
sensitive data. An application running inside a TEE is referred to as a 
Trusted Applications (TA), while a normal application running in the 
regular operating system is referred to as an Untrusted Application 
(UA).

The TEE uses hardware to enforce protections on the TA and its data, but
also presents a more limited set of services to applications inside the
TEE than is normally available to UA’s running in the normal operating
system.
   
But not all TEEs are the same, and different vendors may have different
implementations of TEEs with different security properties, different
features, and different control mechanisms to operate on TAs. Some
vendors may themsleves market multiple different TEEs with different
properties atuned to different markets. A device vendor may integrate
one or more TEEs into their devices depending on market needs.

To simplify the life of developers and service providers interacting
with TAs in a TEE, an interoperable protocol for managing TAs running in
different TEEs of various devices is needed. In this TEE ecosystem,
there often arises a need for an external trusted party to verify the
identity, claims, and rights of SPs, devices, and their TEEs. This
trusted third party is the Trusted Application Manager (TAM).   

The This protocol addresses the following problems:

  - A Service Provider (SP) intending to provide services through a TA
    to users of a device needs to determine security-relevant
    information of a device before provisioning their TA to the TEE
    within the device. Examples include the verification of the device
    'root of trust' and the type of TEE included in a device.

  - A TEE in a device needs to determine whether a Service Provider (SP)
    that wants to manage an TA in the device is authorized to manage TAs
    in the TEE, and what TAs the SP is permitted to manage.

  - The parties involved in the protocol must be able to attest that a
    TEE is genuine and capable of providing the security protections
    required by a particular TA.

  - A Service Provider (SP) must be able to deterine if a TA exists (is
    installed) on a device (in the TEE), and if not, install the TA in
    the TEE.

  - A Service Provider (SP) must be able to check whether a TA in a
    device’s TEE is the most up-to-date version, and if not, update the
    TA in the TEE.

  - A Service Provider (SP) must be able to remove a TA in a device’s
    TEE if the SP is no longer offering such services or the services
    are being revoked from a particular user (or device). For example,
    if a subscription or contract for a particular service has expired,
    or a payment by the user has not been completed or has been recinded.

  - A Service Provider (SP) must be able to define the relationship
    between cooperating TAs under the SP’s control, and specify whether
    the TAs can communicate, share data, and/or share key material.

#  Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", 
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", 
and "OPTIONAL" in this document are to be interpreted as described 
in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear 
in all capitals, as shown here.

The following terms are used:

  - Client Application: An application running on a rich OS, such 
    as an Android, Windows, or iOS  application.

  - Device: A physical piece of hardware that hosts a TEE along with
    a rich OS.

  - Agent: An application running in the rich OS allowing the message 
    protocol exchange between a TAM and a TEE in a device. A TEE is 
    responsible to processing relayed messages and for returning
    an appropriate reponse.

  - Rich Execution Environment (REE): An environment that is provided 
    and governed by a typical OS (Linux, Windows, Android, iOS, etc.), 
    potentially in conjunction with other supporting operating systems 
    and hypervisors; it is outside of the TEE. This environment and 
    applications running on it are considered un-trusted.

  - Secure Boot Module (SBM): A firmware in a device that delivers 
    secure boot functionality. It is generally signed and can be 
    verified whether it can be trusted.

  - Service Provider (SP): An entity that wishes to supply Trusted 
    Applications to remote devices. A Service Provider requires the 
    help of a TAM in order to provision the Trusted Applications to 
    the devices.

  - Trust Anchor: A root certificate that can be used to validate its 
    children certificates. It is usually embedded in a device or 
    configured by a TAM for validating the trust of a remote 
    entity's certificate.

  - Trusted Application (TA): An Application that runs in a TEE.

  - Trusted Execution Environment (TEE): An execution environment that 
    runs alongside of, but is isolated from, an REE. A TEE has security 
    capabilities and meets certain security-related requirements. It 
    protects TEE assets from general software attacks, defines rigid 
    safeguards as to data and functions that a program can access, 
    and resists a set of defined threats. It should have at least
    the following three properties:

    (a) A device unique credential that cannot be cloned;
    
    (b) Assurance that only authorized code can run in the TEE;
    
    (c) Memory that cannot be read by code outside of TEE.

    There are multiple technologies that can be used to implement 
    a TEE, and the level of security achieved varies accordingly.

  - Trusted Firmware (TFW): A signed SBM firmware that can be verified 
    and is trusted by a TEE in a device.

This document uses the following abbreviations:

  - CA: Certificate Authority

  - REE: Rich Execution Environment

  - SD: Security Domain 

  - SP: Service Provider

  - SBM: Secure Boot Module

  - TA: Trusted Application

  - TEE: Trusted Execution Environment

  - TFW: Trusted Firmware

  - TAM: Trusted Application Manager

# Scope and Assumptions 


This specification assumes that an applicable device is equipped with
one or more TEEs and each TEE is pre-provisioned with a device-unique
public/private key pair, which is securely stored. This key pair is
referred to as the 'root of trust' for remote attestation of
the associated TEE in a device by an TAM.

A Security Domain (SD) concept is used as the security boundary inside
a TEE for trusted applications. Each SD is typically associated with
one TA provider as the owner, which is a logical space that contains a
SP's TAs. One TA provider may request to have multiple SDs in a TEE.
One SD may contain multiple TAs. Each Security Domain requires the
management operations of TAs in the form of installation, update and
deletion.

A TA binary and configuration data can be from two sources:

1. A TAM supplies the signed and encrypted TA binary

2. A Client Application supplies the TA binary

The architecture covers the first case where the TA binary and 
configuration data are delivered from a TAM. The second case calls 
for an extension when a TAM is absent.

Messages exchange with a TAM require some transport and HTTPS is one 
commonly used transport.

# Use Cases

## Payment

A payment application in a mobile device requires high security and
trust about the hosting device. Payments initiated from a mobile
device can use a Trusted Application running inside TEE in the device
to provide strong identification and proof of transaction.

For a mobile payment application, some biometric identification
information could also be stored in the TEE. The mobile payment
application can use such information for authentication.


A secure user interface (UI) may be used in a mobile device to
prevent malicious software from stealing sensitive user input data.
Such an application implementation often relies on TEE for user
input protection.

## Authentication

For better security of authentication, a devices may store its 
sensitive authentication keys inside a TEE of the device, providing
hardware-protected security key strength and trusted execution code.

## Internet of Things

Internet of Things (IoT) has been posing threats to networks and 
national infrastructures because of existing weak security in devices. 
It is very desirable that IoT devices can prevent a malware from 
stealing or modifying sensitive data such as authentication credentials 
in the device. A TEE can be the best way to implement such IoT 
security functions.

TEEs could be used to store variety of sensitive data for IoT devices.
For example, a TEE could be used in smart door locks to store a user's
biometric information for identification, and for protecting access
the locking mechanism. Bike-sharing is another example that shares
a similar usage scenario.

## Confidential Cloud Computing

A tenant can store sensitive data in a TEE in a cloud computing
server such that only the tenant can access the data, preventing
the cloud host provider from accessing the data. A tenant can
run TAs inside a server TEE for secure operation and enhanced
data security. This provides benefits not only to tenants with
better data security but also to cloud host provider for reduced
liability and increased cloud adoption.

# Architecture

## System Components 

The following are the main components in the system.

  - TAM:  A TAM is responsible for originating and coordinating lifecycle
    management activity on a particular TEE on behalf of a Service
    Provider or a Device Administrator.  For example, a payment
    application provider, which also provides payment service as a
    Service Provider using its payment TA, may choose to use a TAM
    that it runs or a third party TAM service to distribute and
    update its payment TA application in payment user devices.  The
    payment SP isn't a device administrator of the user devices.  A
    user who chooses to download the payment TA into its devices acts
    as the device administrator, authorizing the TA installation via
    the downloading consent.  The device manufacturer is typically
    responsible for embedding the TAM trust verification capability
    in its device TEE.

    A TAM may be used by one SP or many SPs where a TAM may run as a
    Software-as-a-Service (SaaS).  A TAM may provide Security Domain
    management and TA management in a device for the SD and TAs that
    a SP owns.  In particular, a TAM typically offers over-the-air
    update to keep a SP's TAs up-to-date and clean up when a version
    should be removed.  A TEE administrator or device administrator
    may decide TAMs that it trusts to manage its devices.

  - Certification Authority (CA):  Certificate-based credentials used for
    authenticating a device, a TAM and an SP.  A device embeds a list
    of root certificates (trust anchors), from trusted CAs that a TAM
    will be validated against.  A TAM will remotely attest a device
    by checking whether a device comes with a certificate from a CA
    that the TAM trusts.  The CAs do not need to be the same;
    different CAs can be chosen by each TAM, and different device CAs
    can be used by different device manufacturers.

  - TEE:  A TEE in a device is responsible for protecting applications
    from attack, enabling the application to perform secure
    operations.

  - REE:  The REE in a device is responsible for enabling off-device
    communications to be established between a TEE and TAM.  The
    architecture does not assume or require that the REE or Client
    Applications is secure.

  - Agent:  A Client Application is expected to communicate with a TAM to
    request TAs that it needs to use.  The Client Application needs
    to pass the messages from the TAM to TEEs in the device.  This
    calls for a component in REE that the Client Application can use
    to pass messages to TEEs.  An Agent is this component to fill the
    role.  In other words, an Agent is an application in the REE or
    software library that can simply relays messages from a Client
    Application to a TEE in the device.  A device usually comes with
    only one active TEE.  A TEE that supports may provide such an
    Agent to the device manufacturer to be bundled in devices.  Such
    a compliant TEE must also include an Agent counterpart, namely, a
    processing module inside the TEE, to parse TAM messages sent
    through the Agent.  An Agent is generally acting as a dummy
    relaying box with just the TEE interacting capability; it doesn't
    need and shouldn't parse protocol messages.

  - Device Administrator:  A device owner or administrator may want to
    manage what TAs allowed to run in its devices.  A default list of
    allowed TA trust root CA certificates is included in a device by
    the device's manufacturer, which may be governed by the device
    carriers sometimes.  There may be needs to expose overriding
    capability for a device owner to decide the list of allowed TAs
    by updating the list of trusted CA certificates.

  - Secure Boot:  Secure boot must enable authenticity checking of TEEs
    by the TAM.  Note that some TEE implementations do not require
    secure boot functionality.

## Entity Relations

This architecture leverages asymmetric cryptography to
authenticate a device towards a TAM. Additionally, a TEE
in a device authenticates a TAM provider and TA signer. The
provisioning of trust anchors to a device may different from
one use case to the other. The device administrator may want to
have the capability to control what TAs are allowed.
A device manufacturer enables verification of the TA signers
and TAM providers; it may embed a list of default trust anchors
that the signer of an allowed TA's signer certificate should
chain to. A device administrator may choose to accept a subset
of the allowed TAs via consent or action of downloading.

~~~~
PKI    CA    -- CA                                 CA --
        |    |                                         |
        |    |                                         |
        |    |                                         |
Device  |    |   ---    Agent / Client App   ---       |
SW      |    |   |                             |       |
        |    |   |                             |       |
        |    |   |                             |       |
        |    -- TEE                           TAM-------
        |
        |
       FW
~~~~
{: #entities title="Entities"}

~~~~
 (App Developer)    (App Store)    (TAM)     (Device with TEE)  (CAs)
        |                                            |
        |                               --> (Embedded TEE cert) <--
        |                                            |
        | <------------------------------  Get an app cert ----- |
        |                           | <--  Get a TAM cert ------ |
        |
1. Build two apps:
    Client App
       TA
        |
        |
   Client App -- 2a. --> | ----- 3. Install -------> |
      TA ------- 2b. Supply ------> | 4. Messaging-->|
        |                |          |                |
~~~~
{: #experience title="Developer Experience"}

{{experience}} shows an application developer building
two applications: 1) a rich Client Application; 2) a TA
that provides some security functions to be run inside
a TEE. At step 2, the application developer uploads the
Client Application (2a) to an Application Store. The Client
Application may optionally bundle the TA binary. Meanwhile,
the application developer may provide its TA to a TAM provider
that will be managing the TA in various devices. 3. A user
will go to an Application Store to download the Client
Application. The Client Application will trigger TA installation
by calling TAM. This is the step 4. The Client Application
will get messages from TAM, and interacts with device
TEE via an Agent.

The following diagram will show a system diagram about
the entity relationships between CAs, TAM, SP and devices.

~~~~
        ------- Message Protocol  -----
        |                             |
        |                             |
 --------------------           ---------------   ----------
 |  REE   |  TEE    |           |    TAM      |   |  SP    |
 |  ---   |  ---    |           |    ---      |   |  --    |
 |        |         |           |             |   |        |
 | Client | SD (TAs)|           |   SD / TA   |   |  TA    |
 |  Apps  |         |           |     Mgmt    |   |        |
 |   |    |         |           |             |   |        |
 |   |    |         |           |             |   |        |
 |        | Trusted |           |  Trusted    |   |        |
 | Agent  |  TAM/SP |           |   FW/TEE    |   |        |
 |        |   CAs   |           |    CAs      |   |        |
 |        |         |           |             |   |        |
 |        |TEE Key/ |           |  TAM Key/   |   |SP Key/ |
 |        |  Cert   |           |    Cert     |   | Cert   |
 |        | FW Key/ |           |             |   |        |
 |        |  Cert   |           |             |   |        |
 --------------------           ---------------   ----------
              |                        |              |
              |                        |              |
        -------------              ----------      ---------
        | TEE CA    |              | TAM CA |      | SP CA |
        -------------              ----------      ---------
~~~~
{: #keys title="Keys"}

In the previous diagram, different CAs can be used for different
types of certificates.  Messages are always signed, where the signer
key is the message originator's private key such as that of a TAM,
the private key of a trusted firmware (TFW), or a TEE's private key.

The main components consist of a set of standard messages created by
a TAM to deliver device SD and TA management commands to a device,
and device attestation and response messages created by a TEE that
responds to a TAM's message.

It should be noted that network communication capability is generally
not available in TAs in today's TEE-powered devices.  The networking
functionality must be delegated to a rich Client Application.  Client
Applications will need to rely on an agent in the REE to interact
with a TEE for message exchanges.  Consequently, a TAM generally
communicates with a Client Application about how it gets messages
that originates from TEE inside a device.  Similarly, a TA or TEE
generally gets messages from a TAM via some Client Application,
namely, an agent in this protocol architecture, not directly from the
internet.

It is imperative to have an interoperable protocol to communicate
with different TEEs in different devices that a Client Application
needs to run and access a TA inside a TEE.  This is the role of the
agent, which is a software component that bridges communication
between a TAM and a TEE.  The agent does not need to know the actual
content of messages except for the TEE routing information.

## Trust Anchors in TEE

Each TEE comes with a trust store that contains a whitelist of root
CA certificates that are used to validate a TAM's certificate.  A TEE
will accept a TAM to create new Security Domains and install new TAs
on behalf of a SP only if the TAM's certificate is chained to one of
the root CA certificates in the TEE's trust store.

A TEE's trust store is typically preloaded at manufacturing time.  It
is out of the scope in this document to specify how the trust store
should be updated when a new root certificate should be added or
existing one should be updated or removed.  A device manufacturer is
expected to provide its TEE trust store live update or out-of-band
update to devices.

Before a TAM can begin operation in the marketplace to support TEE-
powered devices with a particular TEE, it must obtain a TAM
certificate from a CA that is listed in the trust store of the TEE.

## Trust Anchors in TAM

The trust anchor store in a TAM consists of a list of CA certificates
that sign various device TEE certificates.  A TAM decides what
devices it will trust the TEE in.

## Keys and Certificate Types

This architecture leverages the following credentials, which allow
delivering end-to-end security without relying on any transport
security.

~~~~
+-------------+----------+--------+-------------------+-------------+
| Key Entity  | Location | Issuer | Checked Against   | Cardinality |
| Name        |          |        |                   |             |
+-------------+----------+--------+-------------------+-------------+
| 1. TFW key  | Device   | FW CA  | A white list of   | 1 per       |
| pair and    | secure   |        | FW root CA        | device      |
| certificate | storage  |        | trusted by TAMs   |             |
|             |          |        |                   |             |
| 2. TEE key  | Device   | TEE CA | A white list of   | 1 per       |
| pair and    | TEE      | under  | TEE root CA       | device      |
| certificate |          | a root | trusted by TAMs   |             |
|             |          | CA     |                   |             |
|             |          |        |                   |             |
| 3. TAM key  | TAM      | TAM CA | A white list of   | 1 or        |
| pair and    | provider | under  | TAM root CA       | multiple    |
| certificate |          | a root | embedded in TEE   | can be used |
|             |          | CA     |                   | by a TAM    |
|             |          |        |                   |             |
| 4. SP key   | SP       | SP     | A SP uses a TAM.  | 1 or        |
| pair and    |          | signer | TA is signed by a | multiple    |
| certificate |          | CA     | SP signer. TEE    | can be used |
|             |          |        | delegates trust   | by a TAM    |
|             |          |        | of TA to TAM. SP  |             |
|             |          |        | signer is         |             |
|             |          |        | associated with a |             |
|             |          |        | SD as the owner.  |             |
+-------------+----------+--------+-------------------+-------------+
~~~~
{: #keytypelist title="Key and Certificate Types"}

1. TFW key pair and certificate:  A key pair and certificate for
    evidence of secure boot and trustworthy firmware in a device.

      - Location:   Device secure storage

      - Supported Key Type:   RSA and ECC

      - Issuer:   OEM CA

      - Checked Against:   A white list of FW root CA trusted by TAMs

      - Cardinality:   One per device

2. TEE key pair and certificate:  It is used for device attestation
    to a remote TAM and SP.

      - This key pair is burned into the device at device manufacturer.
       The key pair and its certificate are valid for the expected
       lifetime of the device.

      - Location:   Device TEE

      - Supported Key Type:   RSA and ECC

      - Issuer:   A CA that chains to a TEE root CA

      - Checked Against:   A white list of TEE root CA trusted by TAMs

      - Cardinality:   One per device

3. TAM key pair and certificate:  A TAM provider acquires a
    certificate from a CA that a TEE trusts.

      - Location:   TAM provider

      - Supported Key Type:   RSA and ECC.

      - Supported Key Size:   RSA 2048-bit, ECC P-256 and P-384.  Other
        sizes should be anticipated in future.

      - Issuer:   TAM CA that chains to a root CA

      - Checked Against:   A white list of TAM root CA embedded in TEE

      - Cardinality:   One or multiple can be used by a TAM

4. SP key pair and certificate:  an SP uses its own key pair and
    certificate to sign a TA.

      - Location:   SP

      - Supported Key Type:   RSA and ECC

      - Supported Key Size:   RSA 2048-bit, ECC P-256 and P-384.  Other
        sizes should be anticipated in future.

      - Issuer:   an SP signer CA that chains to a root CA

      - Checked Against:   A SP uses a TAM.  A TEE trusts an SP by
        validating trust against a TAM that the SP uses.  A TEE trusts
        TAM to ensure that a TA from the TAM is trustworthy.

      - Cardinality:   One or multiple can be used by an SP

## Scalability

This architecture uses a PKI.  Trust anchors exist on the devices to
enable the TEE to authenticate TAMs, and TAMs use trust anchors to
authenticate TEEs.  Since a PKI is used, many intermediate CAs
certificates can chain to a root certificate, each of which can issue
many certificates.  This makes the protocol highly scalable.  New
factories that produce TEEs can join the ecosystem.  In this case,
such a factory can get an intermediate CA certificate from one of the
existing roots without requiring that TAMs are updated with
information about the new device factory.  Likewise, new TAMs can
join the ecosystem, providing they are issued a TAM certificate that
chains to an existing root whereby existing TEEs will be allowed to
be personalized by the TAM without requiring changes to the TEE
itself.  This enables the ecosystem to scale, and avoids the need for
centralized databases of all TEEs produced or all TAMs that exist.

## Message Security

Messages created by a TAM are used to deliver device SD and TA
management commands to a device, and device attestation and response
messages created by the TEE to respond to TAM messages.

These messages are signed end-to-end and are typically encrypted such
that only the targeted device TEE or TAM is able to decrypt and view
the actual content.

## Security Domain Hierarchy and Ownership

The primary job of a TAM is to help an SP to manage its trusted
applications.  A TA is typically installed in an SD.  An SD is
commonly created for an SP.

When an SP delegates its SD and TA management to a TAM, an SD is
created on behalf of a TAM in a TEE and the owner of the SD is
assigned to the TAM.  An SD may be associated with an SP but the TAM
has full privilege to manage the SD for the SP.

Each SD for an SP is associated with only one TAM.  When an SP
changes TAM, a new SP SD must be created to associate with the new
TAM.  The TEE will maintain a registry of TAM ID and SP SD ID
mapping.

From an SD ownership perspective, the SD tree is flat and there is
only one level.  An SD is associated with its owner.  It is up to TEE
implementation how it maintains SD binding information for a TAM and
different SPs under the same TAM.

It is an important decision in this protocol specification that a TEE
doesn't need to know whether a TAM is authorized to manage the SD for
an SP.  This authorization is implicitly triggered by an SP Client
Application, which instructs what TAM it wants to use.  An SD is
always associated with a TAM in addition to its SP ID.  A rogue TAM
isn't able to do anything on an unauthorized SP's SD managed by
another TAM.

Since a TAM may support multiple SPs, sharing the same SD name for
different SPs creates a dependency in deleting an SD.  An SD can be
deleted only after all TAs associated with this SD is deleted.  An SP
cannot delete a Security Domain on its own with a TAM if a TAM
decides to introduce such sharing.  There are cases where multiple
virtual SPs belong to the same organization, and a TAM chooses to use
the same SD name for those SPs.  This is totally up to the TAM
implementation and out of scope of this specification.

## SD Owner Identification and TAM Certificate Requirements

There is a need of cryptographically binding proof about the owner of
an SD in a device.  When an SD is created on behalf of a TAM, a
future request from the TAM must present itself as a way that the TEE
can verify it is the true owner.  The certificate itself cannot
reliably used as the owner because TAM may change its certificate.

To this end, each TAM will be associated with a trusted identifier
defined as an attribute in the TAM certificate.  This field is kept
the same when the TAM renew its certificates.  A TAM CA is
responsible to vet the requested TAM attribute value.

This identifier value must not collide among different TAM providers,
and one TAM shouldn't be able to claim the identifier used by another
TAM provider.

The certificate extension name to carry the identifier can initially
use SubjectAltName:registeredID.  A dedicated new extension name may
be registered later.

One common choice of the identifier value is the TAM's service URL.
A CA can verify the domain ownership of the URL with the TAM in the
certificate enrollment process.

A TEE can assign this certificate attribute value as the TAM owner ID
for the SDs that are created for the TAM.

An alternative way to represent an SD ownership by a TAM is to have a
unique secret key upon SD creation such that only the creator TAM is
able to produce a proof-of-possession (PoP) data with the secret.

## Service Provider Container

A sample Security Domain hierarchy for the TEE is shown in {{SD}}.

~~~~
       ----------
       |  TEE   |
       ----------
           |
           |          ----------
           |----------| SP1 SD1 |
           |          ----------
           |          ----------
           |----------| SP1 SD2 |
           |          ----------
           |          ----------
           |----------| SP2 SD1 |
                      ----------
~~~~
{: #SD title="Security Domain Hiearchy"}

The architecture separates SDs and TAs such that a TAM can only
manage or retrieve data for SDs and TAs that it previously created
for the SPs it represents.

## A Sample Device Setup Flow

Step 1: Prepare Images for Devices

  * 1.  [TEE vendor] Deliver TEE Image (CODE Binary) to device OEM

  * 2.  [CA]  Deliver root CA Whitelist

  * 3.  [Soc]  Deliver TFW Image

Step 2: Inject Key Pairs and Images to Devices

  * 1.  [OEM] Generate Secure Boot Key Pair (May be shared among multiple
       devices)

  * 2.  [OEM] Flash signed TFW Image and signed TEE Image onto devices
       (signed by Secure Boot Key)

Step 3: Setup attestation key pairs in devices

  * 1.  [OEM]  Flash Secure Boot Public Key and eFuse Key (eFuse key is
       unique per device)

  * 2.  [TFW/TEE] Generate a unique attestation key pair and get a
       certificate for the device.

Step 4: Setup trust anchors in devices

  * 1.  [TFW/TEE] Store the key and certificate encrypted with the eFuse
       key

  * 2.  [TEE vendor or OEM] Store trusted CA certificate list into
       devices


# Agent

A TEE and TAs do not generally have capability to communicate to the
outside of the hosting device.  For example, the Global Platform
{{GPTEE}} specifies one such architecture.  This calls for a software
module in the REE world to handle the network communication.  Each
Client Application in REE may carry this communication functionality
but it must also interact with the TEE for the message exchange.  The
TEE interaction will vary according to different TEEs.  In order for
a Client Application to transparently support different TEEs, it is
imperative to have a common interface for a Client Application to
invoke for exchanging messages with TEEs.

A shared agent comes to meed this need.  An agent is an application
running in the REE of the device or a SDK that facilitates
communication between a TAM and TEE.  It also provides interfaces for
TAM SDK or Client Applications to query and trigger TA installation
that the application needs to use.

This interface for Client Applications may be commonly an Android
service call for an Android powered device.  A Client Application
interacts with a TAM, and turns around to pass messages received from
TAM to agent.

In all cases, a Client Application needs to be able to identify an
agent that it can use.


## Role of the Agent 

An agent abstracts the message exchanges with the TEE in a device.
The input data is originated from a TAM that a Client Application
connects.  A Client Application may also directly call Agent for some
TA query functions.

The agent may internally process a request from TAM.  At least, it
needs to know where to route a message, e.g., TEE instance.  It does
not need to process or verify message content.

The agent returns TEE / TFW generated response messages to the
caller.  The agent is not expected to handle any network connection
with an application or TAM.

The agent only needs to return an agent error message if the TEE is
not reachable for some reason.  Other errors are represented as
response messages returned from the TEE which will then be passed to
the TAM.

## Agent Implementation Consideration

   A Provider should consider methods of distribution, scope and
   concurrency on device and runtime options when implementing an agent.
   Several non-exhaustive options are discussed below.  Providers are
   encouraged to take advantage of the latest communication and platform
   capabilities to offer the best user experience.

### Agent Distribution

The agent installation is commonly carried out at OEM time.  A user
can dynamically download and install an agent on-demand.

It is important to ensure a legitimate agent is installed and used.
If an agent is compromised it may drop messages and thereby
introducing a denial of service.

### Number of Agents

We anticipate only one shared agent instance in a device.  The
device's TEE vendor will most probably supply one aent.

With one shared agent, the agent provider is responsible to allow
multiple TAMs and TEE providers to achieve interoperability.  With a
standard agent interface, TAM can implement its own SDK for its SP
Client Applications to work with this agent.

Multiple independent agent providers can be used as long as they have
standard interface to a Client Application or TAM SDK.  Only one
agent is expected in a device.

TAM providers are generally expected to provide SDK for SP
applications to interact with an agent for the TAM and TEE
interaction.

# Attestation

## Attestation Hierarchy

The attestation hierarchy and seed required for TAM protocol
operation must be built into the device at manufacture.  Additional
TEEs can be added post-manufacture using the scheme proposed, but it
is outside of the current scope of this document to detail that.

It should be noted that the attestation scheme described is based on
signatures.  The only encryption that takes place may be the use of a
so-called eFuse to release the SBM signing key and later during the
protocol lifecycle management interchange with the TAM.

SBM attestation can be optional in TEEP architecture where the
starting point of device attestion can be at TEE certfificates.  TAM
can define its policies on what kind of TEE it trusts if TFW
attestation isn't included during the TEE attestation.

###  Attestation Hierarchy Establishment: Manufacture

During manufacture the following steps are required:

1. A device-specific TFW key pair and certificate are burnt into the
     device, encrypted by eFuse.  This key pair will be used for
     signing operations performed by the SBM.

2. TEE images are loaded and include a TEE instance-specific key
     pair and certificate.  The key pair and certificate are included
     in the image and covered by the code signing hash.

3. The process for TEE images is repeated for any subordinate TEEs,
     which are additional TEEs after the root TEE that some devices
     have.

### Attestation Hierarchy Establishment: Device Boot

During device boot the following steps are required:

1. Secure boot releases the TFW private key by decrypting it with
     eFuse.

2. The SBM verifies the code-signing signature of the active TEE and
     places its TEE public key into a signing buffer, along with its
     identifier for later access.  For a TEE non-compliant to this
     architecture, the SBM leaves the TEE public key field blank.

3. The SBM signs the signing buffer with the TFW private key.

4. Each active TEE performs the same operation as the SBM, building
     up their own signed buffer containing subordinate TEE
     information.

### Attestation Hierarchy Establishment: TAM

Before a TAM can begin operation in the marketplace to support
devices of a given TEE, it must obtain a TAM certificate from a CA
that is registered in the trust store of devices with that TEE.  In
this way, the TEE can check the intermediate and root CA and verify
that it trusts this TAM to perform operations on the TEE.

# Acknowledgements

The authors thank Dave Thaler for his very thorough review and many
important suggestions.  Most content of this document are split from
a previously combined OTrP protocol document
{{I-D.ietf-teep-opentrustprotocol}}.  We thank the former co-authors
Nick Cook and Minho Yoo for the initial document content, and
contributors Brian Witten, Tyler Kim, and Alin Mutu.


# Security Considerations

## TA Trust Check at TEE

A TA binary is signed by a TA signer certificate.  This TA signing
certificate/private key belongs to the SP, and may be self-signed
(i.e., it need not participate in a trust hierarchy).  It is the
responsibility of the TAM to only allow verified TAs from trusted SPs
into the system.  Delivery of that TA to the TEE is then the
responsibility of the TEE, using the security mechanisms provided by
the protocol.

We allow a way for an (untrusted) application to check the
trustworthiness of a TA.  An agent has a function to allow an
application to query the information about a TA.

An application in the Rich O/S may perform verification of the TA by
verifying the signature of the TA.  The GetTAInformation function is
available to return the TEE supplied TA signer and TAM signer
information to the application.  An application can do additional
trust checks on the certificate returned for this TA.  It might trust
the TAM, or require additional SP signer trust chaining.

## One TA Multiple SP Case

A TA for multiple SPs must have a different identifier per SP.  A TA
will be installed in a different SD for each respective SP.

## Agent Trust Model

An agent could be malware in the vulnerable Rich OS.  A Client
Application will connect its TAM provider for required TA
installation.  It gets command messages from the TAM, and passes the
message to the agent.

The architecture enables the TAM to communicate with the device's TEE
to manage SDs and TAs.  All TAM messages are signed and sensitive
data is encrypted such that the agent cannot modify or capture
sensitive data.

## Data Protection at TAM and TEE

The TEE implementation provides protection of data on the device.  It
is the responsibility of the TAM to protect data on its servers.

## Compromised CA

A root CA for TAM certificates might get compromised.  Some TEE trust
anchor update mechanism is expected from device OEM.  A compromised
intermediate CA is covered by OCSP stapling and OCSP validation check
in the protocol.  A TEE should validate certificate revocation about
a TAM certificate chain.

If the root CA of some TEE device certificates is compromised, these
devices might be rejected by a TAM, which is a decision of the TAM
implementation and policy choice.  Any intermediate CA for TEE device
certificates SHOULD be validated by TAM with a Certificate Revocation
List (CRL) or Online Certificate Status Protocol (OCSP) method.

## Compromised TAM

The TEE SHOULD use validation of the supplied TAM certificates and
OCSP stapled data to validate that the TAM is trustworthy.

Since PKI is used, the integrity of the clock within the TEE
determines the ability of the TEE to reject an expired TAM
certificate, or revoked TAM certificate.  Since OCSP stapling
includes signature generation time, certificate validity dates are
compared to the current time.

## Certificate Renewal

TFW and TEE device certificates are expected to be long lived, longer
than the lifetime of a device.  A TAM certificate usually has a
moderate lifetime of 2 to 5 years.  A TAM should get renewed or
rekeyed certificates.  The root CA certificates for a TAM, which are
embedded into the trust anchor store in a device, should have long
lifetimes that don't require device trust anchor update.  On the
other hand, it is imperative that OEMs or device providers plan for
support of trust anchor update in their shipped devices.


#  IANA Considerations

This document does not require actions by IANA. 

--- back


# History

RFC EDITOR: PLEASE REMOVE THE THIS SECTION

IETF Drafts

draft-00: 
- Initial working group document
