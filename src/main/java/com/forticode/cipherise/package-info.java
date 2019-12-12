/**
 * The interface to the Cipherise authentication platform.
 *
 * # Cipherise Java SDK
 * ## Version 6.2.0
 * 
 * This SDK is for interacting with a Cipherise server.
 * ## Installation
 * 
 * Add the following to your project's pom.xml.<br/><br/>```<!-- https://developer.cipherise.com/resources/docs/java/ -->```<br/>```<dependency>```<br/>&nbsp;&nbsp;```    <groupId>com.forticode.cipherise_app_sim_int</groupId>```<br/>&nbsp;&nbsp;```    <artifactId>app_sim_int</artifactId>```<br/>&nbsp;&nbsp;```    <version>1.0.0</version>```<br/>```</dependency>```
 * ## Introduction
 * Cipherise does away with passwords and usernames, giving your customers an easy, secure
 * login with their mobile device. With a simple, quick scan of a WaveCode, they can achieve 
 * multi-factor authentication in a single action.
 * 
 *  * Move towards a passwordless experience for your customers.
 *  * No more complicated passwords and usernames.
 *  * A simple, fast experience that is consistent across multiple services.
 *  * No more credential sharing.
 *  
 * By design Cipherise decentralises critical information (identity, credentials and critical 
 * data). Each user's credentials are encrypted and stored in a secure enclave on their personal
 * device. The credentials are never stored elsewhere or transmitted through a browser. This 
 * protects your customers' data and digital identity.
 *
 * ---

 * ## Getting Started
 * Cipherise key concepts can be summarised into the following sections:
 * ### Service Management
 * 
 * The Service Provider can query a Cipherise Server for information to determine 
 * the supported functionality:
 * 
 *   * [Querying a Cipherise server](#QueryCS)
 * 
 * For users to be able to enrol and authenticate to a Service Provider one or more 
 * services need to be created:
 * 
 *   * [Creating new services](#NewService)
 *   * [Revoking services](#RevokeService)
 *  
 * ### User Management
 * In order to interact with Cipherise, a user must be enrolled to a service. This 
 * interaction is the key point in which the trust relationship is established. Future authentications
 * rely on the trust established at enrolment time. For a service that is binding a secure profile to 
 * their Cipherise enrolment, a secure environment must be considered. For example, adding Cipherise
 * to an existing profile in a site may require the user to be logged in. If Cipherise is being used
 * for physical access, it could require being present in the physical environment for enrolment 
 * binding to be accepted. Alternatively, an SMS could also be sent from a profile to the owner's 
 * device.
 * 
 * Some services need not require a personalised account, and it may be sufficient to offer the 
 * instantaneous creation of an anonymous account, simply by the scanning of a WaveCode.
 * 
 *   * [Enrolling a user to a service](#EnrolService)
 *   * [Revoking users from a service](#RevokeUser)
 *    
 * ### Authentication
 * 
 * Once a user is enrolled to a Service Provider, they can authenticate themselves.
 * Cipherise Authentication is bi-directional, meaning that the Service Provider will verify the
 * user's device and the user's device will verify the Service Provider. 
 * Authentication can be used in a variety of ways. It can be simple access control, physical or 
 * digital but it can also be part of a workflow. Workflows could include financial 
 * transaction approval, manager approval or multiple party approval for example.
 * 
 * There are two types of authentication, WaveAuth and Authentication. A PushAuth is 
 * targeted to a specific user, where WaveAuth is performed by displaying a WaveCode image that can be 
 * scanned by a user. Once authenticated, the Service Provider will be informed of the user's 
 * username.
 * 
 *   * [WaveAuth](#WaveAuth)
 *   * [PushAuth](#PushAuth)
 *    
 * ### Advanced Features  
 * 
 * Serialization enables sharing of sessions between separate environments; they can be 
 * serialized and stored by one environment, and then retrieved and deserialized by another 
 * environment. This is most useful for concurrent/cluster environments in which sessions can be 
 * shared between cluster nodes using a central store, such as Redis.
 * 
 *   * [Serialization/Deserialization](#Serialization)
 * 
 * Payload is a feature where a Service Provider can encrypt and send data to a user's device
 * for storage via an authentication or at enrolment, and then retrieved from user device when 
 * required via an authentication. Each individual payload has a maximum size of 4k bytes.
 * Ideally, this would be used by a Service, such that any private or sensitive user data that the 
 * server requires could be held at rest on the user's own device rather than held collectively at
 * the service's storage where the consequences of a hack are far further reaching.
 * Examples of where payload could be used include credit card payment details for a regularly used
 * service, address details or other personally identifying details.
 * 
 *   * [Payload](#Payload)
 * 
 * ---

 * ## Cipherise Functionality
 * 
 *   * [Querying a Cipherise server](#QueryCS)
 *   * [Creating new services](#NewService)
 *   * [Revoking services](#RevokeService)
 *   * [Enrolling a user to a service](#EnrolService)
 *   * [Revoking users from a service](#RevokeUser)
 *   * [WaveAuth](#WaveAuth)
 *   * [Push authentication](#PushAuth)
 *   * [Serialization/Deserialization](#Serialization)
 *   * [Payload](#Payload)
 * 
 * ### <a name="QueryCS"></a>Querying a Cipherise server
 * A Cipherise server can be queried for information about itself and what it supports using 
 * `Client.serverInformation`. See [here](Client.html).
 * This is demonstrated below:
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   Client client = new Client(cipheriseServer);
 *   // Retrieve information from the server and print it out.
 *   ServerInformation info = client.serverInformation();
 *   System.out.println("Server version: ", info.serverVersion);
 *   System.out.println("Build version: ", info.buildVersion);
 *   System.out.println("Minimum app version: ", info.appMinVersion);
 *   System.out.println("Maximum supported payload size: ", info.maxPayloadSize);
 * }}
 * ```
 *
 * ### <a name="NewService"></a>Creating new services
 * The first step to integrating your Service Provider with Cipherise is to create a Cipherise
 * [service](Service.html). This 
 * [service](Service.html) is the Cipherise 
 * representation of your service, and is used by your Service Provider to communicate with the
 * Cipherise system and issue requests.
 * 
 * To achieve this, first create a [Client](Client.html) to connect to a Cipherise server. 
 * A Cipherise server can be created at [developer.cipherise.com](https://developer.cipherise.com).
 * 
 * ```java
 * const client = new cipherise.Client("https://your.cipherise.server.here");
 * ```
 * 
 * Next, use the [Client](Client.html) to create a new 
 * [service](Service.html). A 
 * [service](Service.html) is not stored anywhere by default; in order to retrieve the same 
 * [service](Service.html) again, use 
 * [Service.serialize](Service.html) 
 * to store somewhere and 
 * [Client.deserializeService](Client.html) to restore from 
 * storage.
 * 
 * ```java
 * const service = client.createService("Your Service Here");
 * ```
 * or
 * ```java
 * const serializedService = <insert code to load from database or filesystem>;
 * const service = client.deserializeService(serializedService);
 * ```
 * A complete example using the filesystem follows.
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * import java.io.File;
 * import java.nio.file.Files;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String filename = serviceName + ".service";
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   final String serviceName = "Example Service";
 * 
 *   Client client = new cipherise.Client(cipheriseServer);
 * 
 *   Service service = null;
 *   File file = new File(filename);
 *   if (file.exist()) {
 *     // If the service has been saved to disk, load it.
 *     byte[] serializedService = Files.readAllBytes(file.toPath());
 *     service = client.deserializeService(serializedService);
 *   } else {
 *     // Otherwise, create the service and store it.
 *     service = client.createService(serviceName);
 *     Files.write(file.toPath(), service.serialize());
 *   }
 * }}
 * ```
 * ### <a name="RevokeService"></a>Revoking services
 * A service can revoke itself using [Service.revoke](Service.html). This may be done 
 * when, for example, a Cipherise integration is uninstalled. Revoking a service will disable it and
 * remove it from the list of services on users' devices. It cannot be undone.
 * A complete example of service revocation follows:
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   final String serviceName = "Example Service";
 *   Client client = new Client(cipheriseServer);
 *   Service service = client.createService(serviceName);
 *   service.revoke();
 *   // The service can no longer be used.
 * }}
 * ```
 * ### <a name="EnrolService"></a>Enrolling a user to a service
 * The enrolment process enrols a user to a Cipherise service so that they can use Cipherise to 
 * interact with the service. The enrolment process is multi-step:
 * 
 * 1) An enrolment WaveCode is presented to the user 
 * ([Service.enrolUser](Service.html), 
 * [Enrolment.getWaveCodeUrl](Enrolment.html)). 
 * 
 * 2) The user scans the WaveCode, and the service retrieves the result by long-polling on 
 * validation [Enrolment.validate](Enrolment.html). The result is the URL from which
 * to identicon can be displayed.
 * 
 * 3) The service presents the identicon returned from the validation step. 
 * 
 * 4) The user confirms that it matches the identicon presented on their device. The service presents
 * buttons that can be used to accept or deny the enrolment. See 
 * [Enrolment.confirm](Enrolment.html).
 
 * A complete example of the long-polling workflow follows:
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * import java.util.Scanner;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   final String serviceName = "Example Service";
 *   final String userName = "Test User";
 * 
 *   Client client = new Client(cipheriseServer);
 *   Service service = client.createService(serviceName);
 * 
 *   // (1) Start an enrolment and present the QR code to the user.
 *   Enrolment enrolment = service.enrolUser(userName);
 *   System.out.println("QR code URL:", enrolment.qrCodeUrl);
 *   // (2) Wait for the user to scan and retrieve the identicon.
 *   String identiconUrl = enrolment.validate();
 *   // (3) Display the identicon.
 *   System.out.println("Identicon URL:", identiconUrl); // (3)
 * 
 *   Scanner scan = new Scanner(System.in);
 *   String answer = scan.next();
 * 
 *   // Ask the user whether they want to confirm the enrolment or not.
 *   boolean confirm = answer.toLowerCase().startsWith("y");
 *   // (4) Confirm the enrolment as appropriate.
 *   enrolment.confirm(confirm);
 *   rl.close();
 * }}
 * ```
 * ### <a name="RevokeUser"></a>Revoking users from a service
 * A service can revoke enrolled users using [Service.revokeUser](Service.html). 
 * This could be called for a number of reasons. For example, a user leaves an organisation and is no 
 * longer authorised for access. To regain access, the user must re-enrol.
 * 
 * Additionally, the optional `devices` parameter to `revokeUser` can be used to revoke a subset of
 * the user's devices. A potential use for this parameter is to revoke a device that a user has lost.
 * A complete example of user revocation follows:
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   final String serviceName = "Example Service";
 *   final String userName = "Test User";
 * 
 *   Client client = new Client(cipheriseServer);
 *   Service service = client.createService(serviceName);
 * 
 *   // Automatically enrol the user.
 *   Enrolment enrolment = service.enrolUser(userName);
 *   System.out.println("Enrolment QR code URL:", enrolment.qrCodeUrl);
 *   enrolment.validate();
 *   enrolment.confirm(true);
 * 
 *   // Revoke the user.
 *   service.revokeUser(userName);
 * }}
 * ```
 * ### <a name="WaveAuth"></a>Wave authentication
 * WaveAuth is where the user 'waves' their device over the presented coded image. It is
 * ideal to log in with and upon successful authentication, will provide the Service Provider with 
 * the name of the enrolled application user.
 * 
 * The general flow consists of the following steps:
 * 
 * 1) An authentication WaveCode is presented to the user. The WaveCode is an image, and its URL is
 * obtained by initialising the authentication process. Call 
 * [Service.waveAuthenticate](Service.html) and display the image from the 
 * returned data, located at 
 * [Authentication.getWaveCodeUrl](Authentication.html).
 * 
 * 2) The service retrieves the authentication result by calling 
 * [Authentication.authenticate](Authentication.html). Note that this 
 * is a blocking call and will not return until a user has scanned the returned image and completed
 * the authentication challenge, OR until the authentication times out.
 * 
 * 3) The user scans the QR code and completes the authentication challenge.
 * 
 * 4) The service receives the [authentication result](AuthenticationResult.html). It 
 * contains the actual [result of the authentication](Authentication.html), the username and
 * an optional payload response (more in the Payload section).
 * A complete example of the WaveAuth flow is shown (with a preliminary enrolment):
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   final String serviceName = "Example Service";
 *   final String userName = "Test User";
 * 
 *   Client client = new Client(cipheriseServer);
 *   Service service = client.createService(serviceName);
 * 
 *   // Automatically enrol the user.
 *   Enrolment enrolment = service.enrolUser(userName);
 *   System.out.println("Enrolment QR code URL:", enrolment.qrCodeUrl);
 *   enrolment.validate();
 *   enrolment.confirm(true);
 * 
 *   // (1) Start and present wave authentication.
 *   Authentication auth = service.waveAuthenticate(
 *     "Description of the authentication, appears in the app",
 *     "Secondary information, appears in the app",
 *     AuthenticationLevel.OneTiCK
 *   );
 *   System.out.println("Authentication QR code URL:", authentication.qrCodeUrl);
 * 
 *   // (2) Retrieve authentication result.
 *   AuthenticationResult result = auth.authenticate();
 *   System.out.println("Authenticating username:", result.username);
 *   System.out.println(
 *     "Did the authentication succeed?",
 *     result.authenticated == Authenticated.Success
 *   );
 * }}
 * ```
 * ### <a name="PushAuth"></a>PushAuth
 * PushAuth is a Cipherise authentication that is sent to a particular user's device. This 
 * can only be used when the Service wants to target a specific user and the username and device id 
 * are known for that user. Ideally, this is suited for workflow related cases, such as authorising a 
 * banking transaction (targeted user is the owner of the transferring account), or seeking permission
 * for a privileged activity (targeted user is the supervisor of the user seeking permission).
 * 
 * The general flow consists of the following steps:
 * 
 * 1) Look up the username (the name the user was enrolled to Cipherise as) of the authenticating 
 * user.
 * 
 * 2) Get the device id for the user. This can be determined by calling 
 * [Service.getUserDevices](Service.html). Note that there can be more than one
 * device registered to a user. In this situation, the Service will need to determine which one(s) to 
 * send the authentication to.
 * 
 * 3) Send an authentication to the user's device, by calling 
 * [Service.pushAuthenticate](Service.html). This will return an 
 * [Authentication](Authentication.html).
 * 
 * 4) The service retrieves the authentication result by calling 
 * [Authentication.authenticate](Authentication.html). Note that this call is 
 * blocking, awaiting timeouts or the User to complete the authentication on their device.
 * 
 * 5) The user responds to the authentication notification on their device and solves the 
 * authentication challenge on their device.
 * 
 * 6) The [result of the authentication](Authentication.html) contains the username, what the
 * user responded with, and an optional payload response (See more in the [Payload](#Payload) 
 * section).
 * A complete example of the long-polling push authentication flow is shown (with a preliminary 
 * enrolment):
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   final String serviceName = "Example Service";
 *   final String userName = "Test User";
 * 
 *   Client client = new Client(cipheriseServer);
 *   Service service = client.createService(serviceName);
 * 
 *   // Automatically enrol the user.
 *   Enrolment enrolment = service.enrolUser(userName);
 *   System.out.println("Enrolment QR code URL:", enrolment.qrCodeUrl);
 *   enrolment.validate();
 *   enrolment.confirm(true);
 * 
 *   // (1) Retrieve a device.
 *   List<Device> devices = service.getUserDevices(userName);
 *   // Take the last device returned (the most recent device).
 *   Device device = devices[devices.length - 1];
 * 
 *   // (2) Send a push authentication to the device.
 *   Authentication auth = service.pushAuthenticate(
 *     userName,
 *     device,
 *     "Description of the authentication, appears in the app",
 *     "Secondary information, appears in the app",
 *     "Notification message, appears in the push notification",
 *     AuthenticationLevel.OneTiCK
 *   );
 * 
 *   // (3) Retrieve the result of the authentication.
 *   AuthenticationResult result = auth.authenticate();
 *   System.out.println("Authenticating username:", result.username);
 *   System.out.println(
 *     "Did the authentication succeed?",
 *     result.authenticated == Authenticated.Success
 *   );
 * }}
 * ```
 
 * 
 * ### <a name="Serialization"></a>Serialization/deserialization
 * All classes with an extended lifetime (sessions, etc) support serialization and deserialization. 
 * Serialization packs the state of the session into a byte buffer, which can then be stored and 
 * transferred as appropriate. As this buffer consists of raw bytes, care must be taken in transport; 
 * consider encoding as Base64 or hex as required.
 * 
 * These classes feature a `serialize` method, while the "parent" class (e.g. the parent for 
 * `WaveAuth` is `Service`) features the counterpart deserialization method. A full list is
 * supplied below:
 * 
 * * [Service.serialize](Service.html) / 
 * [Client.deserializeService](Client.html)
 * * [Enrolment.serialize](Enrolment.html) / 
 * [Service.deserializeEnrolment](Service.html)
 * * [Authentication.serialize](Authentication.html) / 
 * [Service.deserializeAuthentication](Service.html)
 *  
 * 
 * 
 * For an example of how these methods may be used, please look at the example for 
 * [Creating new services](#creating-new-services).
 *
 * ### <a name="Payload"></a>Payload
 * 
 * Payload data can be supplied to the user's device during 
 * [enrolment](Enrolment.html) and supplied and fetched during authentication, both
 * [PushAuth](Authentication.html) and 
 * [WaveAuth](Authentication.html). Payload data is arbitrary and is 
 * controlled by the Service Provider.
 * A complete example for enrolment follows:
 *
 * ```java
 * package com.forticode.example;
 * 
 * import com.forticode.cipherise.*;
 * 
 * public class Main {
 * public static void main(String[] args) throws CipheriseException, IOException {
 *   final String cipheriseServer = "https://your.cipherise.server.here";
 *   final String serviceName = "Example Service";
 *   final String userName = "Test User";
 * 
 *   Client client = new Client(cipheriseServer);
 *   Service service = client.createService(serviceName);
 * 
 *   // Automatically enrol the user.
 *   Enrolment enrolment = service.enrolUser(userName);
 *   final Map<String, String> payload1 = new HashMap<>();
 *   payload1.put("hello", "world");
 *   System.out.println("Enrolment QR code URL:", enrolment.qrCodeUrl);
 *   enrolment.validate();
 *   enrolment.confirm(true,
 *     new PayloadRequestBuilder().withSet(payload1).build()
 *   );
 * 
 *   // Retrieve a device.
 *   List<Device> devices = service.getUserDevices(userName);
 *   // Take the last device returned (the most recent device).
 *   Device device = devices[devices.length - 1];
 * 
 *   // Send a push authentication to the device.
 *   Authentication auth = service.pushAuthenticate(
 *     userName,
 *     device,
 *     "Description of the authentication, appears in the app",
 *     "Secondary information, appears in the app",
 *     "Notification message, appears in the push notification",
 *     AuthenticationLevel.OneTiCK
 *   );
 * 
 *   // Retrieve the result.
 *   final Map<String, String> payload2 = new HashMap<>();
 *   payload2.put("testing", "this payload");
 *   AuthenticationResult result = auth.authenticate(true,
 *     new PayloadRequestBuilder()
 *       .withGet(new ArrayList<string>(payload1.keySet()))
 *       .withSet(payload2)
 *       .build()
 *   );
 *   System.out.println("Authenticating username:", result.username);
 *   System.out.println(
 *     "Did the authentication succeed?",
 *     result.authenticated == Authenticated.Success
 *   );
 *   System.out.println("Payload stored?", result.payload.set);
 *   System.out.println("Payload retrieved", result.payload.get);
 * }}
 * ```
 */
package com.forticode.cipherise;