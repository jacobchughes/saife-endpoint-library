---
title: SAIFE Endpoint Library v2.0.1 Documentation

language_tabs:
  - cpp: C++
  - java: Java

toc_footers:
  - Version 2.0.1
  - <a href='https://saifeinc.com/developers'>Become a SAIFE Developer</a>
  - <a href='http://github.com/tripit/slate'>Documentation Powered by Slate</a>
  - Copyright 2014-2016 SAIFE, Inc.
  - All Rights Reserved
  - <a href='https://github.com/saifeinc'>Fork on Github</a>

search: true
---

#Introduction

**Welcome to the SAIFE® Endpoint Library!** 

##About the SAIFE® Endpoint Library

SAIFE® is the world’s most complete application security platform.  With its cutting-edge authentication framework, SAIFE provides the most secure way of routing data through the Internet.  Sensitive data – from text messages to documents to streaming video – can be transported with unparalleled privacy and protection.

The SAIFE SDK allows you to easily build, launch, and scale your own secure applications on SAIFE’s communications platform.  As SAIFE’s core communication library, the SAIFE Endpoint Library enables your application’s endpoints to securely communicate with trusted peers over SAIFE’s network.  Integrate the SAIFE Endpoint Library into your code and immediately achieve a significant risk reduction for your data and a new technological advantage for your users.

##Supported Platforms

The SAIFE Endpoint Library is currently available in both C++ and Java, and currently supports Android™, iOS, OS X, and Linux®.

 | Android™ (4.0.3+) | iOS (8.0+) | OS X (10.8+) | Linux®
------------ | ------------- | ------------- | ------------- | -------------
**Architecture** | ARM | ARM (ARMv7, ARMv7s, ARM 64-bit) | x86-64 | x86-64
**Language(s)** | Java | Swift, Objective-C | Java, C++ | Java, C++

##Prerequisites

As the basic unit of identification and validation, the public certificate plays a central role in SAIFE’s trust-centric paradigm.  As such, your application’s endpoints must be able to address each other via certificate, not IP address.

Furthermore, each of your application’s endpoints must be able to generate a keypair on the device.  On-endpoint keypair generation requires that devices be able to generate enough entropy so that private keys are sufficiently random.

##Encryption Strength

The readily available version of the SAIFE Endpoint Library utilizes 128-bit AES encryption.  If you require AES-256 encryption now or in the future, please email us at [sales@saifeinc.com](mailto:sales@saifeinc.com), and we’ll send you an End-User Certificate that you’ll need to sign and email back to us.

##Export Control Restrictions

Please note that SAIFE’s technology – which uses encryption – is subject to export control restrictions from the United States Department of Commerce, among other laws and regulations.  By downloading the SDK, you are required to comply with all applicable restrictions.  Namely, you may not export or transfer the SDK to prohibited countries or persons, nor may you use the SDK for prohibited purposes.  Please see [SAIFE’s Terms of Use](http://saifeinc.com/policies/saife_terms.pdf) for more information.

##About This Documentation

This reference will guide you in integrating the SAIFE Endpoint Library into your application.  Code snippets accompany each applicable section, with tabs for C++ and Java.  The documentation is divided into the following sections:

* [Getting Started](#getting-started): Instructions for downloading and unpacking the SAIFE Endpoint Library
* [Library Overview](#library-overview): An overview of the SAIFE interface and the endpoint state transition model
* [Typical Application Tasks](#typical-application-tasks): Descriptions and code snippets of common coding tasks
* [Additional Resources](#additional-resources): A listing of resources for additional support
* [Release Notes](#release-notes): A brief release history
* [Acknowledgements](#acknowledgements): A listing of open-source projects used to build the SAIFE Endpoint Library

#Getting Started

##Creating a SAIFE Developer Account

To be able to download the SAIFE SDK, you must first create a free SAIFE Developer account via the [Sign Up page](http://saifeinc.com/developers/signup/).  Registering takes less than a minute.  In most cases, you’ll instantly receive an email containing a link for downloading the SAIFE SDK; if you do not, your account may require some additional processing on our end.  Click the **download** link, opening a download page.  In the download page, click the **Download** button to download the SDK as a single .zip file.

##Unpacking the SAIFE Endpoint Library

The downloaded .zip file contains the SAIFE Endpoint Library in both C++ and Java, which each language having a 64-bit Linux version, a 64-bit Darwin version, and documentation.  Extract the .zip file specific to your target.  You can make a dedicated SAIFE directory on your machine or use a system location.

Each .zip file contains header files and precompiled library files:
* the C++/Darwin folder contains an **include** folder (with header files) and a **lib** folder (with dynamic library files);
* the C++/Linux folder contains an **include** folder (with header files) and a **lib** folder (with shared object files);
* the Java/Darwin folder contains Java .jar files and a **lib** folder (with dynamic library files); and
* the Java/Linux folder contains Java .jar files and a **lib** folder (with shared object files).

##Creating a SAIFE Management Account

After downloading the SAIFE SDK, you’ll want to create a free SAIFE Management account through the [SAIFE Management Dashboard](https://dashboard.saifeinc.com/#/).  The SAIFE Management Dashboard – which provides an intuitive interface for managing your application’s endpoints – will make it easier to test your application.  For testing purposes, you’ll want to create an initial organization and secure contact group in your SAIFE Management Dashboard.  Your endpoints will require an organization in order to be provisioned, and will require a group in order to communicate with other endpoints.

For detailed instructions on setting up a SAIFE Management account and setting up your application through the SAIFE Management Dashboard, please refer to the [SAIFE Management API documentation](http://saifeinc.com/developers/libraries/management/).  After initial testing, you can use the SAIFE Management API to build a custom management interface or to create automated functionality, if required.

#Library Overview

##The SAIFE Interface

Your application will use a single interface (**SaifeInterface**) to command and control the SAIFE Endpoint Library.  The SAIFE interface is an aggregation of sub-interfaces, each of which encapsulates a specific set of functions.  These sub-interfaces include:

* the SAIFE Management Interface (**SaifeManagementInterface**), which contains the methods used to manage the state of the SAIFE Endpoint Library and communication with SAIFE’s network;
* the SAIFE Messaging Interface (**SaifeMessagingInterface**), which contains the methods used to secure messages between endpoints;
* the SAIFE Contact Interface (**SaifeContactServiceInterface**), which contains the methods used to address endpoints; and
* the SAIFE Session Interface (**SaifeSecureSessionInterface**), which contains the methods used to secure sessions between endpoints.

The SAIFE Endpoint Library uses the factory method – via the SAIFE factory class (**SaifeFactory**) – for creating instances of SaifeInterface.

##Endpoint State Transition Model

The SAIFE Endpoint Library defines eight endpoint states.

###Provisioning States

Each of your endpoints will progress through four states during the provisioning process: Null, Unkeyed, Unprovisioned and Provisioned.  Provisioning is the act of an endpoint establishing an identity with SAIFE’s network.

1. An endpoint that has not been loaded with your application is in the **Null** state.
2. Upon installation of your application, the endpoint will transition to the **Unkeyed** state.
	* An endpoint may also be in this state if its keypair has been removed as a result of revocation; in this case, the application must create a keypair and restart.
3. When the endpoint generates a public/private keypair and certificate signing request (CSR), it will transition to the **Unprovisioned** state.
	* The public key is used to encrypt data that is intended for the private key of a receiving endpoint, while the private key is used to decrypt data that has been encrypted with the corresponding public key.
4. In order to transition to the **Provisioned** state, the endpoint must submit its CSR to management services (the SAIFE Management Dashboard), which will then validate the endpoint by signing its public certificate.
	* The public certificate is a cryptographic fingerprint that binds the endpoint’s identity with its public key, providing a means for SAIFE’s network to identify and authenticate the endpoint.
	* Management services will send the signed public certificate – along with initial configuration data (such as revocation lists and Continuum server lists) – to the endpoint.

###Subscription States

The provisioned endpoint will either be in the **Subscribed** or **Unsubscribed** state, depending on its subscription.  Subscription is the act of an endpoint registering with SAIFE’s network to receive the secure messages that have been assigned to it.

###Presence States

The provisioned endpoint will also either be in the **Registered** or **Unregistered** state, depending on its presence.  Presence, which is necessary for the establishment of secure streaming sessions, is the act of an endpoint registering its online status with SAIFE’s network.  Presence allows SAIFE’s network to map an endpoint without sharing or storing its IP address.

#Typical Application Tasks

##Basic Application Tasks

For every application built with the SAIFE Endpoint Library, there are common application tasks that will need to be coded, including initializing the SAIFE Endpoint Library, generating a keypair, updating SAIFE data, unlocking SAIFE, and synchronizing contacts.

###Initializing the SAIFE Endpoint Library

```c++
try {
  // Create instance of SAIFE. A log manager may be optionally specified to redirect SAIFE logging.
  SaifeFactory factory;
  saife_ptr = factory.ConstructLocalSaife(NULL);

  // Set SAIFE logging level
  saife_ptr->SetSaifeLogLevel(LogSinkInterface::SAIFE_LOG_WARNING);

  // Initialize the SAIFE interface
  SaifeManagementState state = saife_ptr->Initialize(defaultKeyStore);
} catch (InvalidManagementStateException& e) {
  std::cerr << e.error() << std::endl;
} catch (SaifeInvalidCredentialException& e) {
  std::cerr << e.error() << std::endl;
} catch (...) {
  std::cerr << "Failed to initialize library with unexpected error" << std::endl;
}
```

```java
try {
  // final LogSinkManager logMgr = LogSinkFactory.constructFileSinkManager(defaultKeyStore + "/log");
  // final LogSinkManager logMgr = LogSinkFactory.constructConsoleSinkManager();

  // Create instance of SAIFE. A log manager may be optionally specified to redirect SAIFE logging.
  saife = SaifeFactory.constructSaife(null);

  // Set SAIFE logging level
  saife.setSaifeLogLevel(LogLevel.SAIFE_LOG_WARNING);

  // Initialize the SAIFE interface

  final ManagementState state = saife.initialize(defaultKeyStore);
} catch (final InvalidManagementStateException e) {
  e.printStackTrace();
} catch (final InvalidCredentialException e) {
  e.printStackTrace();
} catch (final IOException e) {
  e.printStackTrace();
}
```

Upon installation, your application must first initialize the SAIFE Endpoint Library.  This allows the endpoint to transition from the Null state to the Unkeyed state.

Initializing the SAIFE Endpoint Library involves:

* constructing an instance of the SAIFE Endpoint Library (using SaifeFactory);
* optionally setting the desired logging level; and
* initializing SaifeInterface.

If an error is returned, this indicates that the SAIFE Endpoint Library failed to initialize correctly; the log must be analyzed to figure out the reason for failure.

###Generating a Keypair

```c++
if (state == saife::SAIFE_UNKEYED) {
  // The UNKEYED state is returned when SAIFE doesn't have a public/private key pair.

  // Setup the DN attributes to be used in the X509 certificate.
  const DistinguishedName dn("HelloWorldApp");

  // Setup an optional list of logical addresses associated with this SAIFE end point.
  const std::vector<SaifeAddress> address_list;

  // Generate the public/private key pair and certificate signing request.
  CertificateSigningRequest *certificate_signing_request = new CertificateSigningRequest();
  saife_ptr->GenerateSmCsr(dn, defaultPassword, address_list, certificate_signing_request);

  // Add additional capabilities to the SAIFE capabilities list that convey the application specific capabilities.
  std::vector< std::string > capabilities = certificate_signing_request->capabilities();
  capabilities.push_back("com::saife::demo::echo");

  // Provide CSR and capabilities (JSON string) to user for provisioning.
  // The application must restart from the UNKEYED state.
}
```

```java
if (state == ManagementState.UNKEYED) {
  // The UNKEYED state is returned when SAIFE doesn't have a public/private key pair.

  // Setup the DN attributes to be used in the X509 certificate.
  final DistinguishedName dn = new DistinguishedName("SaifeEcho");

  // Setup an optional list of logical addresses associated with this SAIFE end point.
  final List<Address> addressList = new ArrayList();

  // Generate the public/private key pair and certificate signing request.
  final CertificationSigningRequest csr = saife.generateSmCsr(dn, defaultPassword, addressList);

  // Add additional capabilities to the SAIFE capabilities list that convey the application specific capabilities.
  final List<String> capabilities = csr.getCapabilities();
  capabilities.add("com::saife::demo::echo");

  // Provide CSR and capabilities (JSON string) to user for provisioning.
  // The application must restart from the UNKEYED state.
}
```

Upon successful initialization, your application must allow the endpoint to generate a unique public/private keypair and a certificate signing request (CSR), along with a list of application-specific capabilities.  This allows the endpoint to transition from the Unkeyed state to the Unprovisioned state.

In order to create a sufficiently random keypair, the endpoint must generate enough entropy, typically through user interaction.  For more information on generating entropy, please research the available methods for your chosen platform.

Generating a keypair involves:

* prompting the user for a password;
* setting up the distinguished name (DN) attributes (including common name) to be used in the X.509 certificate;
* optionally specifying a list of logical addresses to associate with the endpoint;
* generating a keypair and CSR; and
* augmenting the SAIFE capabilities list with application-specific capabilities.

After completing these steps, the application must restart.

The CSR and list of application-specific capabilities (converted to a JSON string) are necessary for the provisioning process (and transitioning to the Provisioned state).  For manual provisioning, the JSON string is provided to the user, allowing for provisioning via the SAIFE Management Dashboard by a designated administrator.  For automated provisioning, the SAIFE Management API can be used to submit the CSR to management services via an HTTPS connection.

###Updating SAIFE Data

```c++
// Periodically update SAIFE data
try {
  saife_ptr->UpdateSaifeData();
} catch (InvalidManagementStateException e) {
  std::cerr << e.error() << std::endl;
} catch (SaifeIoException e) {
  std::cerr << e.error() << std::endl;
}
```

```java
// Periodically update SAIFE data
try {
  saife.updateSaifeData();
} catch (final InvalidManagementStateException e) {
  e.printStackTrace();
} catch (final IOException e) {
  e.printStackTrace();
}
```

Your application must allow the endpoint to periodically download data – including updates to contact lists, revocation lists, and Continuum server lists – from SAIFE’s network.  You may specify the period between downloads based on considerations for power, performance, and bandwidth.

###Unlocking SAIFE

```c++
// Unlock SAIFE library with user's credential
try {
  saife_ptr->Unlock(defaultPassword);
} catch (SaifeInvalidCredentialException e) {
  std::cerr << e.error() << std::endl;
} catch (InvalidManagementStateException e) {
  std::cerr << e.error() << std::endl;
} catch (AdminLockedException e) {
  std::cerr << e.error() << std::endl;
}
```

```java
// Unlock SAIFE library with user's credential
try {
  saife.unlock(defaultPassword);
} catch (final InvalidCredentialException e1) {
  e1.printStackTrace();
} catch (final InvalidManagementStateException e1) {
  e1.printStackTrace();
} catch (final AdminLockedException e1) {
  e1.printStackTrace();
}
```

Your application must be protected by a user password, which is used to unlock access to the endpoint’s public/private keypair.  The password must never be persisted.  Your application may check the lock status and lock access if the user is inactive.

###Synchronizing Contacts

```c++
// Request a contact list re-sync
try {
  saife_ptr->SynchronizeContacts();
} catch (InvalidManagementStateException e) {
  std::cerr << e.error() << std::endl;
}
```

```java
// Request a contact list re-sync
try {
  saife.synchronizeContacts();
} catch (final InvalidManagementStateException e) {
  e.printStackTrace();
}
```

Communication only occurs between peer endpoints within the same secure contact group.  Your application must allow the changes made to an endpoint’s local contact list (such as the addition or deletion of a peer) to be synchronized with the contact list maintained by management services.  Conversely, your application must allow changes made in management services (perhaps through an administrator via the SAIFE Management Dashboard) to be synchronized locally.  When changes to a group occur, the list of friendly public certificates is updated for each affected endpoint.

##Secure Messaging Tasks

If your application is utilizing SAIFE’s secure messaging (for text strings, images, raw sensor measurements, status updates, etc.), application tasks include subscribing for messages and sending/receiving secure messages.

###Subscribing for Messages

```c++
// Subscribe for SAIFE messages
saife_ptr->Subscribe();
```

```java
// Subscribe for SAIFE messages
saife.subscribe();
```

Your application may allow the endpoint to subscribe for messages (thus transitioning from the Unsubscribed state to the Subscribed state).  During the subscription process, the endpoint authenticates itself to SAIFE’s network, and SAIFE’s network authenticates itself to the endpoint.  The endpoint in this state can receive secure messages sent from other endpoints in its secure contact group.  The endpoint must periodically call SAIFE’s network – at an interval specified by your application – to check for any messages addressed to it.

If the endpoint in the Subscribed state does not maintain its subscription via periodic calls to SAIFE’s network, a subscription timeout event will cause a transition back to the Unsubscribed state; your application must monitor the subscription state and re-subscribe if the state changes to Unsubscribed.  If your application does not want to maintain a persistent connection with SAIFE’s network, it may actively unsubscribe for messages.

###Sending Secure Messages

```c++
try {
  SaifeContact contact = saife_ptr->GetContactByAlias(sendTo);
  std::string sendMsg = "one";
  std::vector<uint8_t> msg_bytes(sendMsg.begin(), sendMsg.end());
  saife_ptr->SendMessage(msg_bytes, echoMsgType, contact, 30, 2000, false);
} catch (NoSuchContactException e) {
  std::cout << "Oops .. '" << sendTo << "' no such contact.  Go to the Dashboard to manage contacts." << std::endl;
} catch (SaifeIoException e) {
  std::cout << "Oops ... seems like we couldn't send message." << std::endl;
} catch (LicenseExceededException e) {
  std::cerr << e.error() << std::endl;
}
```

```java
try {
  final Contact contact = saife.getContactByAlias(sendTo);
  final String sendMsg = "one";
  saife.sendMessage(sendMsg.getBytes(), echoMsgType, contact, 30, 2000, false);
} catch (final NoSuchContactException e) {
  System.out.println("Oops .. '" + sendTo + "' no such contact.  Go to the Dashboard to manage contacts.");
} catch (final IOException e) {
  System.out.println("Oops ... seems like we couldn't send message.");
} catch (final LicenseExceededException e) {
  e.printStackTrace();
}
```

Your application may allow the endpoint to send messages to peer endpoints within its secure contact group.  The sending endpoint uses the receiving endpoint’s public key to encrypt – via the AES algorithm – the message that is intended for the private key of the receiving endpoint.  If the receiving endpoint is offline, the message will be temporarily stored (in encrypted form) in SAIFE’s network until the endpoint establishes presence.

###Receiving Secure Messages

```c++
    try {
      std::vector<SaifeMessagingInterface::SaifeMessageData *> msgs;
      saife_ptr->GetMessages(echoMsgType, &msgs);
      for (std::vector<SaifeMessagingInterface::SaifeMessageData*>::iterator iter = msgs.begin();
          iter != msgs.end(); ++iter) {
        SaifeMessagingInterface::SaifeMessageData *msg = *iter;
        std::string msgstr(msg->message_bytes.begin(), msg->message_bytes.end());
        std::cout << "M:" << msg->sender.alias() << " '" << msgstr << "'" << std::endl;
      }
    } catch (NoSuchContactException e) {
      std::cerr << e.error() << std::endl;
    } catch (SaifeIoException e) {
      std::cerr << e.error() << std::endl;
    } catch (InvalidManagementStateException e) {
      std::cerr << e.error() << std::endl;
    }
```

```java
try {
  final List<MessageData> msgs = saife.getMessages(echoMsgType);
  for (final MessageData msg : msgs) {
    System.out.println("M:" + msg.sender.getAlias() + " '" + new String(msg.message) + "'");
  }
} catch (final InterruptedException e) {
  break;
} catch (final IOException e) {
  e.printStackTrace();
} catch (final InvalidManagementStateException e) {
  e.printStackTrace();
}
```

Your application may also allow the endpoint (in the Subscribed state) to receive messages from peer endpoints within its secure contact group.  The receiving endpoint uses its private key to decrypt messages.  Your application may implement the use of delivery confirmations for read messages.

##Secure Session Tasks

If your application is utilizing SAIFE’s secure messaging (for text strings, images, raw sensor measurements, status updates, etc.), application tasks include subscribing for messages and sending/receiving secure messages.

###Enabling Presence

```c++
// Enable presence for the SAIFE application 
try {
  saife_ptr->EnablePresence();
} catch (InvalidManagementStateException e) {
  std::cerr << e.error() << std::endl;
} catch (UnlockRequiredException e) {
  std::cerr << e.error() << std::endl;
}
```

```java
// Enable presence for the SAIFE application
try {
  saife.enablePresence();
} catch (final InvalidManagementStateException e1) {
  e1.printStackTrace();
} catch (final UnlockRequiredException e1) {
  e1.printStackTrace();
}
```

Your application may allow the endpoint to establish presence (thus transitioning from the Unregistered state to the Registered state).  During the registration of presence, the endpoint authenticates itself to SAIFE’s network, and SAIFE’s network authenticates itself to the endpoint.  The endpoint in this state can initiate secure sessions with other endpoints in its secure contact group, as well as accept these sessions.  The endpoint must periodically update it online status with SAIFE’s network at an interval specified by your application.

If the endpoint in the Registered state does not maintain its presence via updates, a registration timeout event will cause a transition back to the Unregistered state.

###Initiating Sessions

```c++
try {
  SaifeContact contact = saife_ptr->GetContactByAlias(sendTo);
  SaifeSecureSessionInterface *session = saife_ptr->ConstructSecureSession();
  session->Connect(contact, SaifeSecureSessionInterface::LOSSY, 10);

  std::string sendMsg = "one";
  std::vector<uint8_t> msg_bytes(sendMsg.begin(), sendMsg.end());
  session->Write(msg_bytes);
  std::cout << "Data >: '" << sendMsg << "'" << std::endl;
  try {
    std::vector< uint8_t > data;
    session->Read(&data, 1024, 5);
    std::string datastr(data.begin(), data.end());
    std::cout << "Data <: '" << datastr << "'" << std::endl;
  } catch (SessionTimeoutException e) {
    std::cout << "Huh ... No big deal." << std::endl;
  }
  session->Close();
  saife_ptr->ReleaseSecureSession(session);

} catch (SessionTimeoutException e) {
  std::cout << "Oops ... seems like we couldn't connect securely." << std::endl;
} catch (PresenceRequiredException e) {
  std::cout << "Oops ... Looks like presence isn't ready." << std::endl;
} catch (NoSuchContactException e) {
  std::cout << "Oops ... Looks like we aren't allowed to securely communicate with this contact yet." << std::endl;
} catch (SaifeIoException e) {
  std::cout << "Oops ... seems like we couldn't connect." << std::endl;
}
```

```java
try {
  final Contact contact = saife.getContactByAlias(sendTo);
  final SecureSession session = saife.constructSecureSession();
  session.connect(contact, TransportType.LOSSY, 10);
  String sendMsg = "one";
  session.write(sendMsg.getBytes());
  System.out.println("Data >: '" + sendMsg + "'");
  try {
    final byte[] data = session.read(1024, 5);
    System.out.println("Data <: '" + new String(data) + "'");
  } catch (final SessionTimeoutException e) {
    System.out.println("Huh ... No big deal.");
  }
  session.close();
  saife.releaseSecureSession(session);
} catch (final SessionTimeoutException e) {
  System.out.println("Oops ... seems like we couldn't connect securely.");
} catch (final PresenceRequiredException e) {
  System.out.println("Oops ... Looks like presence isn't ready.");
} catch (final NoSuchContactException e) {
  System.out.println("Oops ... Looks like we aren't allowed to securely communicate with this contact yet.");
} catch (final IOException e) {
  System.out.println("Oops ... seems like we couldn't connect.");
}
```

Your application may allow the endpoint (in the Registered state) to establish sessions with peer endpoints within its secure contact group.  Before initiating a secure session with another endpoint, the initiating endpoint must reserve a relay session from SAIFE’s network, with the IP address of the relay (in encrypted form) provided to the endpoint.

###Accepting Sessions

```c++
try {
  // Wait for SAIFE clients to connect securely
  SaifeSecureSessionInterface *session = saife_ptr->Accept();
  SaifeContact peer = session->GetPeer();
  std::cout << "Hey ... " << peer.alias() << " just connected." << std::endl;
  // Service session in a new thread
} catch (InvalidManagementStateException e) {
  std::cerr << e.error() << std::endl;
} catch (PresenceRequiredException e) {
  std::cout << "Oops ... Looks like presence isn't ready." << std::endl;
} catch (InvalidSessionState e) {
  std::cerr << e.error() << std::endl;
}
```

```java
try {
  // Wait for SAIFE clients to connect securely
  final SecureSession session = saife.accept();
  final Contact peer = session.getPeer();
  System.out.println("Hey ... " + peer.getAlias() + " just connected. sess: " + session);
  // Service session in a new thread
} catch (final InvalidManagementStateException e) {
  e.printStackTrace();
} catch (final PresenceRequiredException e) {
  System.out.println("Oops ... Looks like presence isn't ready.");
} catch (final InvalidSessionState e) {
  e.printStackTrace();
}
```

Your application may also allow the endpoint (in the Registered state) to accept sessions with peer endpoints within its secure contact group.  After a relay session is reserved, the initiating endpoint provides the targeted endpoint with the encrypted IP address of the relay.  Before the endpoints are added to the relay, the endpoints create – via the ECDH key-agreement protocol – a unique, ephemeral key for the session, allowing all data in transit to be encrypted.  Endpoints can exchange TCP (lossless) and/or UDP (lossy) frames.

#Additional Resources

If you need additional help with the SAIFE Endpoint Library, please check out the following resources:

* the [SAIFE Developer site](http://saifeinc.com/developers/) is a hub for information about the SAIFE SDK, highlighting practical use cases and key features;
* our [GitHub page](https://github.com/saifeinc) showcases some sample applications; and
* the [SAIFE Support Center](https://saife.zendesk.com/hc/en-us) allows you discuss your project, ask questions, and even receive ticket-based support.

You can also call or email us directly:
* (480) 219-0447
* [support@saifeinc.com](mailto:support@saifeinc.com)

#Release Notes

* **Release 2.0.1** of the SAIFE Endpoint Library was created on May 8, 2015.
* **Release 2.0.0** of the SAIFE Endpoint Library was created on March 25, 2015.
* **Release 1.0.0** of the SAIFE Endpoint Library was created on September 15, 2014.

#Acknowledgements

The SAIFE Endpoint Library is built upon several open-source technologies.  SAIFE, Inc. is committed to the open-source community and maintains a public [GitHub page](https://github.com/saifeinc/) where all modifications to the open-source code are posted.

The following is a complete list of open-source projects packaged with our SAIFE Endpoint Library:

* **libroxml** (XML file parsing implementation)
	* Website: [http://www.libroxml.net/](http://www.libroxml.net/)
	* License: [GNU Lesser General Public License (LGPL)](https://www.gnu.org/licenses/lgpl.html)
* **Boost** (C++ libraries)
	* Website: [http://www.boost.org/](http://www.boost.org/)
	* License: [Boost Software License (Version 1.0)](http://www.boost.org/users/license.html)
* **Google Test** (C++ test framework)
	* Website: [https://github.com/google/googletest](https://github.com/google/googletest)
	* License: [SD 2-Clause License](https://opensource.org/licenses/bsd-license.php)
* **Protocol Buffers** (data interchange format)
	* Website: [https://developers.google.com/protocol-buffers/](https://developers.google.com/protocol-buffers/)
	* License: [BSD 3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
* **libcurl** (URL transfer library)
	* Website: [https://curl.haxx.se/libcurl/](https://curl.haxx.se/libcurl/)
	* License: [Copyright](https://curl.haxx.se/docs/copyright.html)
* **rapidjson** (JSON parser/generator)
	* Website: [http://rapidjson.org/](http://rapidjson.org/)
	* License: [MIT License](https://opensource.org/licenses/mit-license.php)
