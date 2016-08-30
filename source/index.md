---
title: SAIFE Endpoint Library v2.1.0 Documentation

language_tabs:
  - cpp: C++
  - java: Java

toc_footers:
  - Version 2.1.0
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

SAIFE® is the world’s most complete application security platform.  With its cutting-edge authentication framework, SAIFE provides the most secure way of sending, receiving, and storing data via the Internet.  Sensitive data – from text messages to documents to streaming video – can be transported with unparalleled privacy and protection.

The SAIFE SDK allows you to easily build, launch, and scale your own secure applications on SAIFE’s communications platform.  As SAIFE’s core communication library, the SAIFE Endpoint Library enables your application’s endpoints to securely communicate with trusted peers over SAIFE’s network.  Integrate the SAIFE Endpoint Library into your code and immediately achieve a significant risk reduction for your data and a new technological advantage for your users.

##Supported Platforms

The SAIFE Endpoint Library is currently available in both C++ and Java, and currently supports Android™, iOS, OS X (macOS), and Linux®.

 | Android™ | iOS | OS X (macOS) | Linux®
------------ | ------------- | ------------- | ------------- | -------------
**Minimum Platform Version** | 4.0.3 (API 14, NDK r10c) | 8.0 | 10.8 | Red Hat® Enterprise Linux® (RHEL)/CentOS 6.6
**Language(s)** | Java | C++, Objective-C, Swift | Java, C++ | Java, C++
**Architecture** | ARM | ARM (ARMv7, ARMv7s, ARM 64-bit) | x86-64 | x86-64

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

To be able to download the SAIFE SDK, you must first create a free SAIFE Developer account via the [Sign Up page](http://saifeinc.com/developers/signup/).  Registering takes less than a minute.  In most cases, you’ll instantly receive an email containing a link for downloading the SAIFE SDK; if you do not, your account may require some additional processing on our end.  Click the **download link**, opening a download page.  In the download page, click the **Download** button to download the SDK as a single .zip file.

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

##Referring to Sample Applications

There are several sample applications on our [GitHub page](https://github.com/saifeinc) that showcase the features of the SAIFE Endpoint Library.  Use these samples as a guide for building your own application.  Sample applications include:

* [SaifeMessageDemo](https://github.com/saifeinc/examples-saife-endpoint-lib/tree/develop/SaifeMessageDemo), demonstrating secure messaging, both point-to-point (in the C++ version) and group (in the Java version);
* [SaifeEchoDemo](https://github.com/saifeinc/examples-saife-endpoint-lib/tree/develop/SaifeEchoDemo), demonstrating secure messaging and sessions;
* [SAIFEDARDemo](https://github.com/saifeinc/examples-saife-endpoint-lib/tree/develop/SAIFEDARDemo), demonstrating secure data at rest (DAR); and
* [SAIFENSDemo](https://github.com/saifeinc/examples-saife-endpoint-lib/tree/develop/SAIFENSDemo), demonstrating secure network share (NS) via Amazon Simple Storage Service (S3).

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
3. When the endpoint generates a cryptographic keypair (public and private keys) and certificate signing request (CSR) based on the public key, it will transition to the **Unprovisioned** state.
	* The public key can be used by a trusted peer to encrypt data intended for the endpoint, while the private key is used to decrypt that data.
4. In order to transition to the **Provisioned** state, the endpoint must submit its CSR to management services (the SAIFE Management Dashboard), which will then validate the endpoint by signing its public certificate.
	* The public certificate is a cryptographic fingerprint that binds the endpoint’s identity with its public key, providing a means for SAIFE’s network to identify and authenticate the endpoint.
	* Management services will send the signed public certificate – along with initial configuration data (such as certificate revocation lists) – to the endpoint.

###Subscription States

The provisioned endpoint will either be in the **Subscribed** or **Unsubscribed** state, depending on its subscription.  Subscription is the act of an endpoint registering with SAIFE’s network to receive the secure messages that have been assigned to it.

###Presence States

The provisioned endpoint will also either be in the **Registered** or **Unregistered** state, depending on its presence.  Presence, which is necessary for the establishment of secure streaming sessions, is the act of an endpoint registering its online status with SAIFE’s network.  Presence allows SAIFE’s network to map an endpoint without sharing or storing its IP address.

#Typical Application Tasks

##Basic Application Tasks

For every application built with the SAIFE Endpoint Library, there are common application tasks that will need to be coded, including initializing the SAIFE Endpoint Library, generating a keypair, updating SAIFE data, and unlocking SAIFE.

###Initializing the SAIFE Endpoint Library

```c++
try {
  LogSinkFactory logSinkFactory;
  //LogSinkManagerInterface *logMgr = logSinkFactory.CreateFileSink(defaultKeyStore + "/log");
  LogSinkManagerInterface *logMgr = logSinkFactory.CreateConsoleSink();

  // Create instance of SAIFE. A log manager may be optionally specified to redirect SAIFE logging.
  SaifeFactory factory;
  saife_ptr = factory.ConstructLocalSaife(logMgr);

  // Set SAIFE logging level.
  saife_ptr->SetSaifeLogLevel(LogSinkInterface::SAIFE_LOG_WARNING);

  // Initialize the SAIFE interface.
  SaifeManagementState state = saife_ptr->Initialize(defaultKeyStore);

  if (state != saife::SAIFE_UNKEYED && state != saife::SAIFE_INITIALIZED) {
    std::cerr << "failed to initialize SAIFE" << std::endl;
    return 1;
  }

} catch (InvalidManagementStateException& e) {
  std::cerr << e.error() << std::endl;
} catch (SaifeInvalidCredentialException& e) {
  std::cerr << e.error() << std::endl;
} catch (...) {
  std::cerr << "Failed to initialize library with unexpected error" << std::endl;
}
```

```java
// Initialize SAIFE.
try {
  // final LogSinkManager logMgr = LogSinkFactory.constructFileSinkManager(defaultKeyStore + "/log");
  // final LogSinkManager logMgr = LogSinkFactory.constructConsoleSinkManager();

  // Create instance of SAIFE. A log manager may be optionally specified to redirect SAIFE logging.
  saife = SaifeFactory.constructSaife(logMgr);

  // Set SAIFE logging level.
  saife.setSaifeLogLevel(LogLevel.SAIFE_LOG_WARNING);

  // Initialize the SAIFE interface at the specified path.
  final ManagementState state = saife.initialize(defaultKeyStorePath);

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
  // Set up the DN attributes to be used in the X.509 certificate.
  const DistinguishedName dn("SaifeEcho");

  // Generate the public/private keypair and certificate signing request.
  CertificateSigningRequest *certificate_signing_request = new CertificateSigningRequest();
  saife_ptr->GenerateSmCsr(dn, defaultPassword, certificate_signing_request);

  // Add additional capabilities to the SAIFE capabilities list that convey the application-specific capabilities.
  std::vector< std::string > capabilities = certificate_signing_request->capabilities();
  capabilities.push_back("com::saife::demo::echo");

  // Provide CSR and capabilities (JSON string) to user for provisioning.
  std::string fName = defaultKeyStore + "/newkey.smcsr";
  std::ofstream f(fName.c_str());
  if (f.is_open()) {
    f << "CSR: " << certificate_signing_request->csr() << std::endl;
    // This should really be done with a proper JSON library.
    f << "CAPS: [";
    for (unsigned int i = 0; i < capabilities.size(); i++) {
      f << "\"" << capabilities[i] << "\"";
      if (i != capabilities.size() - 1) {
        f << ",";
      }
    }
    f << "]" << std::endl;
  }
  f.close();
}
```

```java
// Check the management state.
if (state == ManagementState.UNKEYED) {

  // Set up the DN attributes to be used in the X.509 certificate.
  final DistinguishedName dn = new DistinguishedName("SaifeEcho");

  // Add the required amount of entropy.
  boolean entropic = false;

  CertificationSigningRequest csr = null;

  final FileInputStream fin 
    = new FileInputStream("/dev/urandom");

  byte[] b;

  while (!entropic) {
    try {
      b = new byte[32];
      fin.read(b);

      System.out.println("adding entropy to SAIFE library");
      saife.AddEntropy(b, 4);

      // Generate the public/private keypair and certificate signing request.
      csr = saife.generateSmCsr(dn, defaultPassword);

      entropic = true;
    } catch (final InsufficientEntropyException e) {
      System.out.println(e.getMessage());
      entropic = false;
    } catch (final IOException e) {
      e.printStackTrace();
    }
  }
  try {
    fin.close();
  } catch (final IOException e) {}

  // Add additional capabilities to the SAIFE capabilities list that convey application-specific capabilities.
  final List<String> capabilities = csr.getCapabilities();
  capabilities.add("com::saife::demo::echo");

  // Provide CSR and capabilities (JSON string) to user for provisioning.
  final PrintWriter f = new PrintWriter(defaultKeyStorePath + "/newkey.smcsr");
  f.println("CSR: " + csr.getEncodedCsr());
  final Gson gson = new Gson();
  f.println("CAPS: " + gson.toJson(capabilities));
  f.close();

} else if (state == ManagementState.ERROR) {
  System.out.println("failed to initialize SAIFE");
} else {
```

Upon successful initialization, your application must allow the endpoint to generate a unique keypair and CSR, along with a list of SAIFE capabilities (such as encryption strength, roles, and functionalities).  This allows the endpoint to transition from the Unkeyed state to the Unprovisioned state.

Generating a keypair involves:

* setting up the distinguished name (DN) attributes to be used in the X.509 certificate;
	* The distinguished name structure, which is independent of the SAIFE Management Dashboard, only requires a common name.  The common name is like a nickname for the certificate and is helpful for debugging purposes.  There isn’t a strict format for the common name; for example, it can be a person’s name, an ID, or a location.
* generating entropy; and
	* An appropriate entropy source is necessary to seed the deterministic random bit generator (DRBG) with a sequence of random bytes used to generate the keypair.  Typically, the entropy source is a local system resource, such as the /dev/random special file in Unix-like operating systems or the SecureRandom constructor in Java-like platforms.  It is also possible to utilize user-supplied entropy, which may entail having users draw randomly on the device screen or shake the device, among other means.  An acceptable level of entropy ensures that the private key is sufficiently random (and thus, difficult for a potential attacker to determine).
* augmenting the SAIFE capabilities list with application-specific capabilities.
	* The list of application-specific capabilities allows a SAIFE-enabled endpoint (i.e., an instance of an application built with the SAIFE Endpoint Library) to communicate its feature set to other SAIFE-enabled endpoints for the sake of determining which types of information can be shared.  There isn’t a strict format for the common name; however, it is recommended that you adhere to the namespace conventions for your platform.

After completing these steps, the application must restart.

The CSR (a 376-character string) and SAIFE capabilities list (converted to a JSON string) are necessary for the provisioning process (and transitioning to the Provisioned state).  For manual provisioning, the CSR and capabilities string are provided to the user, allowing the user or a designated administrator to create a certificate in the SAIFE Management Dashboard.  For automated provisioning, the SAIFE Management API (using an API key) can be used to submit the CSR to management services via an HTTPS connection.

###Updating SAIFE Data

```c++
try {
  saife_ptr->UpdateSaifeData();
} catch (InvalidManagementStateException &e) {
  std::cerr << e.error() << std::endl;
} catch (saife::io::IOException &e) {
  std::cerr << e.error() << std::endl;
}
```

```java
// Start a task to periodically update SAIFE data every 10 minutes.
saifeThreadPool.execute(new Runnable() {

  @Override
  public void run() {
    try {
      saife.updateSaifeData();
    } catch (final InvalidManagementStateException e) {
      e.printStackTrace();
    } catch (final IOException e) {
      e.printStackTrace();
    }
    saifeThreadPool.schedule(this, 600, TimeUnit.SECONDS);
  }
});
```

Your application must allow the endpoint to periodically download data – including updates to contact lists, revocation lists, and Continuum server lists – from SAIFE’s network.  You may specify the period between downloads based on considerations for power, performance, and bandwidth.

###Unlocking SAIFE

```c++
// Unlock SAIFE library with user's credential.
try {
  saife_ptr->Unlock(defaultPassword);
} catch (SaifeInvalidCredentialException &e) {
  std::cerr << e.error() << std::endl;
} catch (InvalidManagementStateException &e) {
  std::cerr << e.error() << std::endl;
}
```

```java
// Unlock SAIFE library with user's credential.
try {
  saife.unlock(defaultPassword);
} catch (final InvalidCredentialException e1) {
  e1.printStackTrace();
} catch (final InvalidManagementStateException e1) {
  e1.printStackTrace();
}
```

Your application must be protected by a user password, which is used to unlock access to the endpoint’s public/private keypair.  The password must never be persisted.  Your application may check the lock status and lock access if the user is inactive.

##Secure Messaging Tasks

If your application is utilizing SAIFE’s secure messaging (for text strings, images, raw sensor measurements, status updates, etc.), application tasks include subscribing for messages and sending/receiving secure messages.

###Subscribing for Messages

```c++
// Subscribe for SAIFE messages.
saife_ptr->Subscribe();
```

```java
// Subscribe for SAIFE messages.
saife.subscribe();
```

Your application may allow the endpoint to subscribe for messages (thus transitioning from the Unsubscribed state to the Subscribed state).  During the subscription process, the endpoint authenticates itself to SAIFE’s network, and SAIFE’s network authenticates itself to the endpoint.  The endpoint in this state can receive secure messages sent from other endpoints in its secure contact group.  The endpoint must periodically call SAIFE’s network – at an interval specified by your application – to check for any messages addressed to it.

If the endpoint in the Subscribed state does not maintain its subscription via periodic calls to SAIFE’s network, a subscription timeout event will cause a transition back to the Unsubscribed state; your application must monitor the subscription state and re-subscribe if the state changes to Unsubscribed.  If your application does not want to maintain a persistent connection with SAIFE’s network, it may actively unsubscribe for messages.

###Sending Secure Messages

```c++
try {
  SaifeContact contact = saife_ptr->GetContactByName(sendTo);
  int rcvMsgCnt = 0;
  for (std::vector<std::string>::iterator iter = messageList.begin(); iter != messageList.end(); ++iter) {
    std::string sendMsg = *iter;
    std::vector<uint8_t> msg_bytes(sendMsg.begin(), sendMsg.end());
    saife_ptr->SendMessage(msg_bytes, echoMsgType, contact, 30, 2000, false);
    std::cout << "Msg >: '" << sendMsg << "'" << std::endl;
    std::vector<SaifeMessagingInterface::SaifeMessageData *> rcvMsgs;
    int maxInterval = 0;
    do {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      saife_ptr->GetMessages(echoMsgType, &rcvMsgs);
      ++maxInterval;
    } while (rcvMsgs.size() == 0 && maxInterval < 100);
    for (std::vector<SaifeMessagingInterface::SaifeMessageData*>::iterator iter = rcvMsgs.begin();
          iter != rcvMsgs.end(); ++iter) {
        SaifeMessagingInterface::SaifeMessageData *msg = *iter;
      ++rcvMsgCnt;
      std::string msgstr(msg->message_bytes.begin(), msg->message_bytes.end());
      std::cout << "Msg <: '" << msgstr << "'" << std::endl;
    }
  }
  std::cout << "Ok .. All done.  Sent " << messageList.size() << " messages and received " << rcvMsgCnt << " messages" << std::endl;
} catch (NoSuchContactException e) {
  std::cout << "Oops .. '" << sendTo << "' no such contact.  Go to the Dashboard to manage contacts." << std::endl;
} catch (saife::io::IOException e) {
  std::cout << "Oops ... seems like we couldn't send message." << std::endl;
} catch (LicenseExceededException e) {
  std::cerr << e.error() << std::endl;
}
```

```java
try {
  final Contact contact = saife.getContactByName(sendTo);
  int rcvMsgCnt = 0;
  for (final String sendMsg : messageList) {
    saife.sendMessage(sendMsg.getBytes(), echoMsgType, contact, 30, 2000, false);
    System.out.println("Msg >: '" + sendMsg + "'");
    List<MessageData> rcvMsgs;
    int maxInterval = 0;
    do {
      try {
        Thread.sleep(100);
      } catch (final InterruptedException e) {
      }
      rcvMsgs = saife.getMessages(echoMsgType);
      ++maxInterval;
    } while (rcvMsgs.size() == 0 && maxInterval < 100);
    for (final MessageData rcvMsg : rcvMsgs) {
      ++rcvMsgCnt;
      System.out.println("Msg <: '" + new String(rcvMsg.message) + "'");
    }
  }
  System.out.println("Ok .. All done.  Sent " + messageList.size() + " messages and received " + rcvMsgCnt
      + " messages");
} catch (final NoSuchContactException e) {
  System.out.println("Waiting for echo server '" + sendTo + "' to get into our contact list.");
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
  // Get and echo messages.
  std::vector<SaifeMessagingInterface::SaifeMessageData *> msgs;
  saife_ptr->GetMessages(echoMsgType, &msgs);
  for (std::vector<SaifeMessagingInterface::SaifeMessageData*>::iterator iter = msgs.begin();
      iter != msgs.end(); ++iter) {
    SaifeMessagingInterface::SaifeMessageData *msg = *iter;
    std::string msgstr(msg->message_bytes.begin(), msg->message_bytes.end());
    std::cout << "M:" << msg->sender.name() << " '" << msgstr << "'" << std::endl;
    saife_ptr->SendMessage(msg->message_bytes, msg->message_type, msg->sender, 30, 2000, false);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
} catch (NoSuchContactException &e) {
  std::cerr << e.error() << std::endl;
} catch (saife::io::IOException &e) {
  std::cerr << e.error() << std::endl;
} catch (InvalidManagementStateException &e) {
  std::cerr << e.error() << std::endl;
} catch (LicenseExceededException &e) {
  std::cerr << e.error() << std::endl;
}
```

```java
try {
  // Get and echo messages.
  final List<MessageData> msgs = saife.getMessages(echoMsgType);
  for (final MessageData msg : msgs) {
    System.out.println("M:" + msg.sender.getName() + " '" + new String(msg.message) + "'");
    saife.sendMessage(msg.message, msg.messageType, msg.sender, 30, 2000, false);
  }
  // Check for messages every second.
  Thread.sleep(100);
} catch (final InterruptedException e) {
  break;
} catch (final NoSuchContactException e) {
  System.out.println("Oops .. message client is not in the contact list.  Go to the Dashboard to manage contacts.");
} catch (final IOException e) {
  e.printStackTrace();
} catch (final InvalidManagementStateException e) {
  e.printStackTrace();
} catch (final LicenseExceededException e) {
  e.printStackTrace();
}
```

Your application may also allow the endpoint (in the Subscribed state) to receive messages from peer endpoints within its secure contact group.  The receiving endpoint uses its private key to decrypt messages.  Your application may implement the use of delivery confirmations for read messages.

##Group Messaging Tasks

If your application is utilizing SAIFE’s secure group messaging, application tasks include creating/deleting ad-hoc messaging groups, adding/removing members, sending/receiving secure group messages, and leaving the group.

###Creating an Ad-Hoc Messaging Group

```java
List<Contact> contacts = new Vector<Contact>();
SecureCommsGroup group;

try {
    // add some members to a List
    contacts.add(saife.getContactsByName("client1").get(0));
    contacts.add(saife.getContactsByName("client2").get(0));
    contacts.addAll(saife.getContactsByName("user"));
} catch (final NoSuchContactException nsce) {
    final String m = imse.getMessage();
    System.out.println(m);
} catch (final InvalidManagementStateException imse) {
    final String m = imse.getMessage();
    System.out.println(m);
}

try {
    // creates a secure communications group
    // members *MUST* be in an omnigroup together
    group = saife.createGroup("group1", contacts);
} catch (final ContactGroupNotFoundException cgnfe) {
    final String m = cgnfe.getMessage();
    System.out.println(m);
} catch (final IllegalArgumentException iae) {
    final String m = iae.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
} catch (final KeySizeNotSupportedException ksnse) {
    final String m = ksnse.getMessage();
    System.out.println(m);
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final Exception e) {
    final String m = e.getMessage();
    System.out.println(m);
}
```

Your application may allow the endpoint to set up an ad-hoc messaging group.  All members of this group must be in the same secure contact group (omni type) as defined via management services (the SAIFE Management Dashboard).  The group owner must define the attributes for the group, including a group name, list of member certificates, and group key.  The group owner uses each group member’s public key to encrypt – via the AES algorithm – the attributes for each group member.  The attributes are sent to each group member.  The group owner then creates a multi-destination welcome message for the group, which is encrypted using the group key.

###Deleting an Ad-Hoc Messaging Group

```java
SecureCommsGroup group;
List<String> groups = saife.ListGroups();

try {
    group = saife.getGroup(groups.get(0));
} catch (final GroupNotFoundException gnfe) {
    final String m = gnfe.getMessage();
    System.out.println(m);
}

try {
    // destroy the group
    group.destroy();
} catch (final GroupPermissionDeniedException gpde) {
    final String m = gpde.getMessage();
    System.out.println(m);
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
} catch (final Exception e) {
    final String m = e.getMessage();
    System.out.println(m);
}
```

If the group owner does not want to maintain an ad-hoc messaging group, it may delete the group.

###Adding a Member to an Ad-Hoc Messaging Group

```java
SecureCommsGroup group;
List<String> groups = saife.ListGroups();
Contact contact;

try {
    group = saife.getGroup(groups.get(0));
    contact = saife.getContactsByName("client1").get(0);
} catch (final NoSuchContactException nsce) {
    final String m = nsce.getMessage();
    System.out.println(m);
} catch (final GroupNotFoundException gnfe) {
    final String m = gnfe.getMessage();
    System.out.println(m);
}

try {
    // add member to group
    group.addMember(contact);
} catch (final ContactGroupNotFoundException cgnfe) {
    final String m = cgnfe.getMessage();
    System.out.println(m);
} catch (final GroupPermissionDeniedException gpde) {
    final String m = gpde.getMessage();
    System.out.println(m);
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
} catch (final Exception e) {
    final String m = e.getMessage();
    System.out.println(m);
}
```

Your application may allow the endpoint to add additional members to the ad-hoc messaging group.

###Removing a Member from an Ad-Hoc Messaging Group

```java
SecureCommsGroup group;
List<String> groups = saife.ListGroups();
Contact contact;

try {
    group = saife.getGroup(groups.get(0));
    contact = saife.getContactsByName("client1").get(0);
} catch (final NoSuchContactException nsce) {
    final String m = nsce.getMessage();
    System.out.println(m);
} catch (final GroupNotFoundException gnfe) {
    final String m = gnfe.getMessage();
    System.out.println(m);
}

try {
    // remove member from group
    group.removeMember(contact);
} catch (final GroupPermissionDeniedException gpde) {
    final String m = gpde.getMessage();
    System.out.println(m);
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
} catch (final Exception e) {
    final String m = e.getMessage();
    System.out.println(m);
}
```

Your application may also allow the endpoint to remove members from the ad-hoc messaging group.

###Sending Secure Group Messages

```java
SecureCommsGroup group;
List<String> groups = saife.ListGroups();
String message = "some message";

try {
    group = saife.getGroup(groups.get(0));
} catch (final GroupNotFoundException gnfe) {
    final String m = gnfe.getMessage();
    System.out.println(m);
}

try {
    // send message to the group
    group.sendMessage(message.getBytes());
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
} catch (final Exception e) {
    final String m = e.getMessage();
    System.out.println(m);
}
```

Your application may allow the endpoint to send messages to members of its ad-hoc messaging group.  The sending endpoint uses the group key to encrypt the message for the rest of the group.

###Receiving Secure Group Messages

```java
class MessageListener implements SecureCommsGroupListener {

        public MessageListener() {
        }

        @Override
        public void groupDestroyed(String groupID, String groupName) {
            System.out.println("group was destroyed: " + groupName);
        }

        @Override
        public void groupMemberAdded(String groupID, String groupName,
                Contact newMember) {
            System.out.println("member was added to group: " + newMember + " " 
                    + groupName);
        }

        @Override
        public void groupMemberRemoved(String groupID, String groupName,
                Contact removedMember) {
            System.out.println("member was removed from group: " + groupName + " " 
                    + removedMember);
        }

        @Override
        public void newGroup(String groupID, String groupName) {
            System.out.println("group was created: " + groupName);
        }

        @Override
        public void onMessage(Contact sender, byte[] groupMessage, 
            String groupID, String groupName) {
            System.out.println("Got message");
            System.out.println("received group ID: " + groupID);
            final String msg = sender.getName() + ": " 
                + new String(groupMessage);
            System.out.println(msg);
      }
}

// ...

MessageListener msgList = new MessageListener();
SecureCommsGroupCallback cb =
    SecureCommsGroupCallbackFactory.construct(cb, saife);
try {
    saife.addSecureCommsGroupListener(cb);
} catch (final IllegalArgumentException iae) {
    final String m = iae.getMessage();
    System.out.println(m);
}
```

Your application may also allow the endpoint to receive messages (via callbacks) from members of its ad-hoc messaging group.

###Leaving the Ad-Hoc Messaging Group

```java
SecureCommsGroup group;
List<String> groups = saife.ListGroups();

try {
    group = saife.getGroup(groups.get(0));
} catch (final GroupNotFoundException gnfe) {
    final String m = gnfe.getMessage();
    System.out.println(m);
}

try {
    // leave the group, cannot do it group owner
    group.removeSelft();
} catch (final GroupPermissionDeniedException gpde) {
    final String m = gpde.getMessage();
    System.out.println(m);
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
} catch (final Exception e) {
    final String m = e.getMessage();
    System.out.println(m);
}
```

Your application may allow the endpoint (if not the group owner) to leave the ad-hoc messaging group.

##Secure Session Tasks

If your application is utilizing SAIFE’s secure sessions (for voice calls, video calls, video feeds, etc.), application tasks include enabling presence and initializing/accepting secure sessions.

###Enabling Presence

```c++
// Enable presence for the SAIFE server.
try {
  saife_ptr->EnablePresence();
} catch (InvalidManagementStateException &e) {
  std::cerr << e.error() << std::endl;
} catch (UnlockRequiredException &e) {
  std::cerr << e.error() << std::endl;
}
```

```java
// Enable presence for the SAIFE server.
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
  SaifeContact contact = saife_ptr->GetContactByName(sendTo);
  SaifeSecureSessionInterface *session = saife_ptr->ConstructSecureSession();
  session->Connect(contact, SaifeSecureSessionInterface::LOSSY, 10);
  int rcvMsgCnt = 0;
  for (std::vector<std::string>::iterator iter = messageList.begin(); iter != messageList.end(); ++iter) {
    std::string sendMsg = *iter;
    std::vector<uint8_t> msg_bytes(sendMsg.begin(), sendMsg.end());
    session->Write(msg_bytes);
    std::cout << "Data >: '" << sendMsg << "'" << std::endl;
    try {
      std::vector< uint8_t > data;
      session->Read(&data, 1024, kSessionReadTimeMs);
      std::string datastr(data.begin(), data.end());
      std::cout << "Data <: '" << datastr << "'" << std::endl;
      ++rcvMsgCnt;
    } catch (SessionTimeoutException e) {
      std::cout << "Huh ... missed an echo response.  No big deal." << std::endl;
    }
  }
  std::cout << "Ok .. All done.  Sent " << messageList.size() << " messages and received " << rcvMsgCnt
      << " messages" << std::endl;
  session->Close();
  saife_ptr->ReleaseSecureSession(session);

} catch (SessionTimeoutException e) {
  std::cout << "Timeout attempting to connect session" << std::endl;
} catch (PresenceRequiredException e) {
  std::cout << "Presence is not available" << std::endl;
} catch (NoSuchContactException e) {
  std::cout << "Contact was not found" << std::endl;
} catch (saife::io::IOException e) {
  std::cout << "I/O Error while attempting to connect session" << std::endl;
}
```

```java
try {
  // Get the contact from the contact list.
  final Contact contact = saife.getContactByName(sendTo);

  System.out.println("Establishing a session with echo server " + contact.getName());
  final SecureSession session = saife.constructSecureSession();

  // Try to connect for 10 seconds.
  session.connect(contact, TransportType.LOSSLESS, 10);
  System.out.println("Established a session with echo server " + contact.getName());

  int rcvMsgCnt = 0;
  for (final String sendMsg : messageList) {

    // Write session data to the echo server.
    session.write(sendMsg.getBytes());
    System.out.println("Data >: '" + sendMsg + "'");

    try {

      // Try to read session data back from the echo server, try for 5 seconds.
      final byte[] data = session.read(1024, 5000);
      System.out.println("Data <: '" + new String(data) + "'");
      ++rcvMsgCnt;
    } catch (final SessionTimeoutException e) {
      System.out.println("Huh ... missed an echo response.  No big deal.");
    }
  }
  System.out.println("Ok .. All done.  Sent " + messageList.size() + " messages and received " + rcvMsgCnt
      + " messages");
  session.close();
  saife.releaseSecureSession(session);

} catch (final SessionTimeoutException e) {
  System.out.println("Oops ... seems like we couldn't connect securely.");
} catch (final PresenceRequiredException e) {
  System.out.println("Oops ... Looks like presence isn't ready.");
} catch (final NoSuchContactException e) {
  System.out.println("Oops ... Looks like echo server " + sendTo + " is not part of our contact list.");
} catch (final IOException e) {
  System.out.println("Oops ... seems like we couldn't connect.");
}
```

Your application may allow the endpoint (in the Registered state) to establish sessions with peer endpoints within its secure contact group.  Before initiating a secure session with another endpoint, the initiating endpoint must reserve a relay session from SAIFE’s network, with the IP address of the relay (in encrypted form) provided to the endpoint.

###Accepting Sessions

```c++
try {
  // Wait for SAIFE clients to connect securely.
  SaifeSecureSessionInterface *session = saife_ptr->Accept();
  SaifeContact peer = session->GetPeer();
  std::cout << "Hey ... " << peer.name() << " just connected." << std::endl;
  std::thread handleSessThread(handleSession, session);
  handleSessThread.detach();
} catch (InvalidManagementStateException e) {
  std::cerr << e.error() << std::endl;
} catch (PresenceRequiredException e) {
  std::cout << "Oops ... Looks like presence isn't ready." << std::endl;
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
} catch (InvalidSessionState e) {
  std::cerr << e.error() << std::endl;
}
```

```java
try {
  // Wait for SAIFE clients to connect securely.
  final SecureSession session = saife.accept();

  final Contact peer = session.getPeer();
  System.out.println("Just received a incoming session from echo client " + peer.getName() + ". sess: " + session);

  // Now give the session over to the SessionHandler to be run in a separate thread.
  saifeThreadPool.submit(new SessionHandler(session));

} catch (final InvalidManagementStateException e) {
  e.printStackTrace();
} catch (final InvalidSessionState e) {
  e.printStackTrace();
}
```

Your application may also allow the endpoint (in the Registered state) to accept sessions with peer endpoints within its secure contact group.  After a relay session is reserved, the initiating endpoint provides the targeted endpoint with the encrypted IP address of the relay.  Before the endpoints are added to the relay, the endpoints create – via the ECDH key-agreement protocol – a unique, ephemeral key for the session, allowing all data in transit to be encrypted.  Endpoints can exchange TCP (lossless) and/or UDP (lossy) frames.

##Secure Network Share Tasks

If your application is utilizing SAIFE’s secure network share (for text documents, presentations, spreadsheets, media files, etc.), application tasks include retrieving/creating a secure network share, sharing a secure network share, and writing to/reading from a secure network share.

###Retrieving/Creating a Secure Network Share

```java
// This retrieve or creates a network share manager.
// these will varry with implementation
final String shareID = "some_text";
final String storagePath = "/some/path";

final PersistentStore persistentStore = new Persister();
final NetworkShare ns;

// create a manager
final NetworkShareManager mgr = new NetworkShareManager(saife);

try {
    ns = mgr.getNetworkShare(shareID, storagePath, persistentStore);
} catch (final IOException e1) {
    System.out.println("getNetworkShare IO exception!");
} catch (final NetworkShareDoesNotExistException e1) {
    System.out.println("NetworkShareDoesNotExistException.  Creating "
            + "NetworkShare.");
    try {
        ns = mgr.createNetworkShare(shareID, storagePath, persistentStore);
    } catch (final IOException e) {
        System.out.println("CreateNetworkShare IOException");
        e.printStackTrace();
    } catch (final NetworkShareExistsException e) {
        System.out.println("Unrecoverable NetworkShareExistsException, "
                + "since GetNetworkShare also failed.");
    }
}

// implementation differs for each application
public class Persister implements PersistentStore {
    public Persister() {}
    @Override 
    public List<PersistedObject> getObjects(final String storagePath,
            final String prefix) throws IOException {}
    @Override
    public releaseObjects(final List<PersistedObject> releaseObjects) {}
    @Override
    public InputStream getInputStream(final PersistedObject object) {}
    @Override
    public InputStream getInputStream(final String storagePath,
            final String name) throws IOException {}
    @Override 
    public void releaseInputStream(final InputStream is) {}
    @Override
    public OutputStream getOutputStream(final PersistedObject object)
            throws IOException {}
    @Override
    public OutputStream getOutputStream(final String storagePath,
            final String name) throws IOException {}
    @Override
    public void releaseOutputStream(final OutputStream os) {}
    @Override
    public void deleteObject(final PersistedObject) throws IOException {}
    @Override
    public void deleteObject(final String storagePath, final String name) 
            throws IOException {}
}
```

Your application may allow the endpoint to retrieve/create a secure network share.  Secure network share requires the establishment of a file-sharing system, either via public cloud (using a cloud service provider, such as Amazon Simple Storage Service) or private cloud (using an enterprise network).

###Sharing a Secure Network Share

```java
final String shareID = "some_text";
final String storagePath = "/some/path";
final PersistentStore persistentStore = new Persister();

final NetworkShare ns;
final Contact contact;

try {
    // get the network share
    ns = mgr.getNetworkShare(shareID, storagePath, persistentStore);
    // get the contact
    contact = saife.getContactsByName("some_name").get(0);
} catch (final NoSuchContactException nsce) {
    final String m = nsce.getMessage();
    System.out.println(m);
} catch (final InvalidManagementStateException imse) {
    final String m = imse.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
} catch (final NetworkShareDoesNotExistException nsdnee) {
    final String m = nsdnee.getMessage();
    System.out.println(m);
}

try {
    // add the contact to the share
    ns.addMember(contact);
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final NotAllowedException nae) {
    final String m = nae.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
}
```

Your application may allow the endpoint to share a secure network share with other endpoints within its secure contact group.  The network share owner must create the initial version of a 512-bit network share key (NSK).  The initiating endpoint uses each group member’s public key to wrap – via the AES algorithm – the NSK for each member.  The wrapped NSK is sent to each group member.

###Removing Members from Secure Network Share 

Your application may also allow the endpoint to remove members from the secure network share.

###Writing to Secure Network Share

Your application may allow the endpoint to write a file to the secure network share.  The endpoint uses the NSK to encrypt the file – via the AES algorithm – before writing it to the share.  The endpoint then sends a secure message to all peers indicating that a new file has been written to network storage.

###Reading from Secure Network Share

Your application may also allow the endpoint to read a file from the secure network share.  Upon receiving a secure notification message from a peer, the endpoint navigates to the location of the new or edited file, downloads the file, and decrypts the file using the NSK.

##Secure Data-at-Rest Tasks

If your application is utilizing SAIFE’s secure data-at-rest capability, application tasks include creating and deleting a secure volume.

###Creating a Secure Volume

```java
// create a volume
final SecureVolume.VolumeType vt = SecureVolume.VolumeType.PERMANENT;
final String vFile = "/some/path/to/file";
final String volLabel = "some_label";
// must be multiple of 1024, at least 10MB
final long volSize = 1024 * 1024 * 10;   

final SecureVolume vol;

try {
    vol = saife.createVolume(vt, vFile, volLabel, volSize);
} catch (final ProfisioningRequredException pre) {
    final String m = pre.getMessage();
    System.out.println(m);
} catch (final UnlockRequiredException ure) {
    final String m = ure.getMessage();
    System.out.println(m);
} catch (final IllegalArgumentException iae) {
    final String m = iae.getMessage();
    System.out.println(m);
} catch (final IOException ioe) {
    final String m = ioe.getMessage();
    System.out.println(m);
}
```

Your application may allow the endpoint to create a secure volume.  To secure data at rest (DAR) on the device, the endpoint uses its volume key (generated during the provisioning process) to encrypt – via the AES algorithm – the file.

###Deleting a Secure Volume

```java
// delete a volume
final SecureVolume vol;
final List<SecureVolume> volList;

volList = saife.listVolumes();
vol = volList.get(0);

saife.removeVolume(vol);
```

Your application may also allow the endpoint to delete a secure volume.

##Zero-Knowledge Password Reset Tasks

```c++
//We arbitrarily set the password to 16 random (printable) characters
static const int keystorePasswordLength = 16;

//Here's where we store the keystore password.
static const std::string passwordFileName = "saife_password";

/** The SAIFE interface */
static SaifeInterface* saife_ptr = NULL;

//Inlines for class definition
std::string generateNewKeystorePassword();
void writePasswordToFile(std::string);

class MyPwdResetListener : public saife::PasswordResetListenerInterface
{
public:
    MyPwdResetListener() { }
    virtual ~MyPwdResetListener() { }
    virtual void PasswordResetProcessed() {

        std::cout << "The SDK has received and processed a password reset message." << std::endl;
        std::string newPwd = generateNewKeystorePassword();
        std::cout << "Changing the keystore password to the following: " << newPwd << std::endl;
        
        //NOTE: The new user credential is required to be set before the keystore
        //locks.  It should be done as soon as possible alleviate any possibility
        //of the user not seeing the password reset prompt or catastrophic failure
        //of the application (device crashes, user reboots phone, etc.).  It is
        //possible to leave the keystore in a state that is not recoverable if the
        //keystore's credentials are not entered as soon as possible.
        saife_ptr->SetUserCredential(newPwd);

        std::cout << "Writing new password to the password file." << std::endl;
        writePasswordToFile(newPwd);
    }
};

std::string readPasswordFromFile()
{
    std::ifstream pwdFile(passwordFileName);
    if (pwdFile)
    {
        std::string password((std::istreambuf_iterator<char>(pwdFile)),
                             std::istreambuf_iterator<char>());
        pwdFile.close();
        return password;
    }
    throw std::runtime_error("Password file not found");
}

//This is only for example purposes.  Under normal circumstances, you would
//never write the keystore password to a plain text file.  We do this for
//illustration purposes only!
void writePasswordToFile(std::string newPassword)
{
    std::ofstream pwdFile(passwordFileName, std::ofstream::trunc);
    if (pwdFile)
    {
        pwdFile << newPassword;
        pwdFile.close();
    }
}

//The following was adapted from:
//http://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
//In a real application, the user would be prompted for the password
std::string generateNewKeystorePassword()
{
    static const std::string alphanums =
            "0123456789"
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    std::random_device r;
    std::seed_seq seed{r(), r(), r(), r(), r(), r(), r(), r()};
    std::mt19937 rng(seed);
    std::uniform_int_distribution<> pick(0, alphanums.size() - 1);

    std::string newPwd;

    for (int i = 0; i < keystorePasswordLength; i++)
        newPwd += alphanums[pick(rng)];

    return newPwd;
}

//There are multiple ways of generating entropy on devices.  This code is
//intended for illustrative purposes only.  Use at your own risk. For more
//information, please contact SAIFE directly to have a more detailed
//discussion about the generation of random data as well as the platform
//considerations that must be considered when generating random data.
void addEntropy()
{
    std::random_device r;
    std::seed_seq seed{r(), r(), r(), r(), r(), r(), r(), r()};
    std::mt19937 rng(seed);

    std::vector<uint8_t> randomData;
    for (int i = 0; i < 4096; i++) {
        randomData.push_back(rng());
    }

    saife_ptr->AddEntropy(randomData, 4.0);
}

void generateSigningRequest(const std::string defaultKeyStore)
{
    // Setup the DN attributes to be used in the X509 certificate.
    const DistinguishedName dn("SaifeZKPR-cpp");

    // In order to generate a good private key, the SAIFE SDK needs a good
    // source of random data.  Some random sources are better than others.
    // It is up to the developer to determine exactly how and where to obtain
    // a source of *good* randomness.
    addEntropy();

    // Generate the public/private key pair and certificate signing request.
    CertificateSigningRequest *certificate_signing_request = new CertificateSigningRequest();
    std::string password = generateNewKeystorePassword();
    writePasswordToFile(password);
    saife_ptr->GenerateSmCsr(dn, password, certificate_signing_request);

    // Add additional capabilities to the SAIFE capabilities list that convey the application specific capabilities.
    std::vector< std::string > capabilities = certificate_signing_request->capabilities();
    capabilities.push_back("com::saife::demo::zkpr");

    // Provide CSR and capabilities (JSON string) to user for provisioning.
    // The application must restart from the UNKEYED state.
    std::string fName = defaultKeyStore + "/newkey.smcsr";
    std::ofstream f(fName.c_str());
    if (f.is_open()) {
      f << "CSR: " << certificate_signing_request->csr() << std::endl;
      // This should really be done with a proper JSON library.
      f << "CAPS: [";
      for (unsigned int i = 0; i < capabilities.size(); i++) {
        f << "\"" << capabilities[i] << "\"";
        if (i != capabilities.size() - 1) {
          f << ",";
        }
      }
      f << "]" << std::endl;
    }
    f.close();
    delete certificate_signing_request;
}

int main(int argc, char *argv[]) {



  /** The default path where all persisted SAIFE data is written. */
  const std::string defaultKeyStore = ".SaifeStore";

  //Custom password reset listener to handle password resets
  MyPwdResetListener pwdResetListener;

  try {
    LogSinkFactory logSinkFactory;
    LogSinkManagerInterface *logMgr = logSinkFactory.CreateConsoleSink();

    // Create instance of SAIFE. A log manager may be optionally specified
    // to redirect SAIFE logging.
    SaifeFactory factory;
    saife_ptr = factory.ConstructLocalSaife(logMgr);

    // Set SAIFE logging level
    saife_ptr->SetSaifeLogLevel(LogSinkInterface::SAIFE_LOG_INFO);

    // Initialize the SAIFE interface
    SaifeManagementState state = saife_ptr->Initialize(defaultKeyStore);

    if (state != saife::SAIFE_UNKEYED && state != saife::SAIFE_INITIALIZED) {
      std::cerr << "failed to initialize SAIFE" << std::endl;
      return 1;
    }

    if (state == saife::SAIFE_UNKEYED) {
        std::cout << "SAIFE Endpoint Library is not keyed. Generating signing request." << std::endl;
        //The UNKEYED state is returned when SAIFE doesn't have a
        //public/private key pair.
        generateSigningRequest(defaultKeyStore);

        //Application will then terminate to allow time to get the CSR signed
        //by the SAIFE dashboard.  Log into https://dashboard.saifeinc.com
        //and create a new certificate using the CSR and capabilities located
        //in .SaifeStore/newkey.smcsr
        std::cout << "A certificate signing request has been generated." << std::endl;
        std::cout << "Please create a new certificate via the SAIFE Dashboard" << std::endl;
        std::cout << "with the signing request located in: " << defaultKeyStore << std::endl;

    } else if (state == saife::SAIFE_INITIALIZED) {
        //SAIFE is now initialized

        //Add our password reset handler
        saife_ptr->AddPasswordResetListener(&pwdResetListener);

        //Update the data associated with SAIFE.  This includes getting the
        //provisioning information after the certificate is signed
        saife_ptr->UpdateSaifeData();

        //Subscribe for SAIFE Messages.  We want to respond quickly to password
        //reset messages so we establish a persistent messaging connection to the
        //SAIFE Messaging Server
        saife_ptr->Subscribe();

        //Now attempt to unlock the keystore with the password in the file
        try {
            std::string keystorePassword = readPasswordFromFile();
            std::cout << "Attempting to unlock the keystore with password: " << keystorePassword << std::endl;
            saife_ptr->Unlock(keystorePassword);
            std::cout << "Keystore unlocked!" << std::endl;

        } catch (saife::SaifeInvalidCredentialException sice) {
            std::cout << "InvalidCredentialException caught!" << std::endl;
            std::cout << "The keystore password contained within the password file was not correct." << std::endl;
            std::cout << "You need to reset the certificate\'s password from the SAIFE Dashboard." << std::endl;
            std::cout << "Please visit https://dashboard.saifeinc.com to perform the zero knowledge" << std::endl;
            std::cout << "password reset (zkpr)." << std::endl;
        }

        std::cout << std::endl << "Waiting for incoming SAIFE messages..." << std::endl;

        //We wait until the user breaks (CNTRL-BREAK) or kills the processes
        while (1) {
            saife_ptr->UpdateSaifeData();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
  } catch (InvalidManagementStateException& e) {
    std::cerr << e.error() << std::endl;
  } catch (SaifeInvalidCredentialException& e) {
    std::cerr << e.error() << std::endl;
  } catch (...) {
    std::cerr << "Failed to initialize library with unexpected error" << std::endl;
  }

  return 0;
}
```

```java
public class SaifeZKPR {

    // directory to save the keystore in
    public static final String keystoreDir = ".SaifeStore";

    // password file
    public static final String SAIFE_PASSWORD_FILE = "saife_password";

    public static boolean isPasswordReset = false;

    // password used to unlock SAIFE
    public static String password;

    // instance of the SAIFE library
    public static Saife saife;

    // logger from SAIFE
    public static Logger logger;

    public static Random rand = new Random();

    // SAIFE keeps a weak reference to these objects, we have to keep strong
    // references
    private static PasswordListener pwlist;
    private static PasswordResetCallback pwcb;

    public static void main(final String[] args) {
        if (initSaife()) {
            try {
                // read current password from file
                Scanner pwin = new Scanner(new FileInputStream("saife_password"));
                password = pwin.next();
                pwin.close();

                // unlock using the read password
                saife.unlock(password);

                // update data
                saife.updateSaifeData();

                // subscribe to receive messages
                saife.subscribe();

                // try 5 times to wait for subscription state change
                SubscriptionState state = saife.getSubscriptionState();
                int tries = 5;
                while (state != SubscriptionState.SUBSCRIBED_AUTHENTICATED && tries > 0) {
                    Thread.sleep(2_000);
                    tries--;
                    state = saife.getSubscriptionState();
                }

                if (state != SubscriptionState.SUBSCRIBED_AUTHENTICATED) {
                    logger.error("SAIFE did not subscribe in time");
                    System.exit(1);
                }

                logger.info("SAIFE library is ready to be reset");
                logger.info("Please issue a Password Reset for the certificate \"" + saife.certName() + "\" via the dashboard(https://dashboard.saifeinc.com)");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                System.exit(1);
            } catch (InvalidCredentialException e) {
                e.printStackTrace();
                System.exit(1);
            } catch (InvalidManagementStateException e) {
                e.printStackTrace();
                System.exit(1);
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }

        while (!isPasswordReset) {
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                // do nothing, still want to busy-wait so program ends when
                // password is reset
            }
        }
    }

    /**
     * helper method to initialize and/or generate keys for saife library
     *
     * @return true if and only if saife is initialized properly
     */
    private static boolean initSaife() {
        try {
            // create a logger
            LogSinkManager logMgr = LogSinkFactory.constructConsoleSinkManager();

            // construct SAIFE with logger
            saife = SaifeFactory.constructSaife(logMgr);

            // set logging level of SAIFE
            // saife.setSaifeLogLevel(LogLevel.SAIFE_LOG_TRACE);
            saife.setSaifeLogLevel(LogLevel.SAIFE_LOG_INFO);

            logger = saife.getLogger("SaifeZKPR");

            // get password from file
            // NOTE: in real applications, the user is prompted for a password
            Scanner pwin = new Scanner(new FileInputStream("saife_password"));
            password = pwin.next();
            pwin.close();

            // initialize SAIFE
            ManagementState state = saife.initialize(keystoreDir);

            if (state == ManagementState.UNKEYED) {
                // SAIFE is unkeyed, generate a CSR and manually sign

                final DistinguishedName dn = new DistinguishedName("SaifeZKPR");

                boolean entropic = false;

                CertificationSigningRequest csr = null;

                FileInputStream fin = new FileInputStream("/dev/urandom");

                byte[] b;

                // add the required amount of entropy to the SAIFE instance
                while (!entropic) {
                    try {
                        b = new byte[32];
                        fin.read(b);

                        logger.info("Adding entropy");
                        saife.AddEntropy(b, 4);

                        csr = saife.generateSmCsr(dn, password);

                        entropic = true;
                    } catch (InsufficientEntropyException e) {
                        logger.error(e.getMessage());
                    }
                }

                fin.close();

                final List<String> capabilities = csr.getCapabilities();
                capabilities.add("com::saife::demo::zkpr");

                final PrintWriter f = new PrintWriter(keystoreDir + "/newkey.smcsr");
                f.println("CSR: " + csr.getEncodedCsr());
                final Gson gson = new Gson();
                f.println("CAPS: " + gson.toJson(capabilities));
                f.close();

                logger.info("new cert has been generated at " + keystoreDir + " /newkey.smcsr,  please provision at https://dashboard.saifeinc.com and re-run the program");
                return false;
            } else if (state == ManagementState.ERROR) {
                logger.error("SAIFE failed to initialize");
                return false;
            } else {
                // SAIFE is initialized, add password reset listener
                pwlist = new PasswordListener();
                pwcb = PasswordCallbackFactory.construct(pwlist, saife);
                saife.addPasswordResetListener(pwcb);

                return true;
            }
        } catch (InvalidManagementStateException imse) {
            final String m = imse.getMessage();
            logger.error(m);
            return false;
        } catch (final IOException ioe) {
            final String m = ioe.getMessage();
            logger.error(m);
            return false;
        } catch (final InvalidCredentialException ice) {
            final String m = ice.getMessage();
            logger.error(m);
            return false;
        } 
    }

    /**
     * used to generate or prompt for a new password
     *
     * @param length  length of the password to generate
     * @return  string of password
     */
    private static String getNewPassword() {
        // this is where a new password is created, whether it be generated or
        // prompted from the user. In this example, it is a randomly generated,
        // mixed-case, alphanumeric string. This code is highly dependent on
        // your own use-case.
        int length = 10;
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            // 62
            int c = rand.nextInt(61) + 48;
            if (c > 57) {
                c += 7;
            }
            if (c > 90) {
                c += 6;
            }
            password.append((char) c);
        }
        logger.info("new password is \"" + password.toString() + "\"");
        try {
            setPasswordFile(password.toString());   // the use of a password file is for example only
        } catch (FileNotFoundException e) {
            logger.error("password file cannot be found");
        }
        return password.toString();
    }

    static class PasswordListener implements PasswordResetListener {

        @Override
        public void passwordResetProcessed() {
            // here is where you handle the Password Reset request, getting a
            // new password, and setting the new user credentials
            logger.debug("Password Reset request received");
            String newPass = getNewPassword();
            try {
                logger.debug("setting new password");
                // IMPORTANT
                // set the user credential here or the password reset request
                // serves no purpose and nothing is changed
                saife.setUserCredential(newPass);

                logger.info("Password was successfully reset");
                isPasswordReset = true;
            } catch (InvalidManagementStateException e) {
                logger.error("Password Reset failed due to InvalidManagementStateException");
            }
        }

    }

    /**
     * set the file to contain the new password
     * this is for examples only, and is a terrible way to store passwords
     *
     * @param password  the new password to set
     */
    private static void setPasswordFile(final String password) throws FileNotFoundException {
        File pwfile = new File(SAIFE_PASSWORD_FILE);
        pwfile.delete();
        PrintStream pwout = new PrintStream(pwfile);
        pwout.println(password);
        pwout.close();
    }
}
```

Your application may utilize SAIFE’s zero-knowledge password reset (ZKPR) capability.  In the event that a user forgets their password for the application, an administrator can allow the user to unlock the endpoint, all without revealing the user’s application password.

Password reset capability is enabled during the provisioning process, when the endpoint generates a ZKPR key that is split into two halves. One half is stored on the endpoint, while the other half is securely sent to management services via a Continuum server.

The password reset process typically involves the following steps:

1. The user, attempting to unlock the SAIFE-enabled application, realizes that they do not have the correct password.
2. The user contacts their administrator using an out-of-band channel (such as a voice call or email), requesting a password reset.
	* Ideally, an out-of-band authentication mechanism should be used in order to minimize the threat of social engineering.
3. The administrator resets the password for the pertinent certificate, either in the SAIFE Management Dashboard or using the SAIFE Management API directly.
4. Management services sends a hashed, unencrypted password reset message (containing management services’ half of the ZKPR key associated with the endpoint) to the endpoint through SAIFE’s network.
5. The application generates two new password reset splits, securely sending one split to management services through SAIFE’s network.
6. The SAIFE Endpoint Library unlocks itself, and the application prompts the user for a new password.
7. The user enters a new password, allowing for continued normal use of the application.

#Additional Resources

If you need additional help with the SAIFE Endpoint Library, please check out the following resources:

* the [SAIFE Developer site](http://saifeinc.com/developers/) is a hub of resources for integrating the SAIFE Endpoint Library into your code;
* our [GitHub page](https://github.com/saifeinc) showcases some sample applications; and
* the [SAIFE Support Center](https://saife.zendesk.com/hc/en-us) allows you discuss your project, ask questions, and receive ticket-based support.

You can also call or email us directly:

* (480) 219-0447
* [support@saifeinc.com](mailto:support@saifeinc.com)

#Release Notes

* **Release 2.1.0** of the SAIFE Endpoint Library was created on November 6, 2015.
* **Release 2.0.0** of the SAIFE Endpoint Library was created on March 5, 2015.
* **Release 1.0.0** of the SAIFE Endpoint Library was created on September 29, 2014.

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
