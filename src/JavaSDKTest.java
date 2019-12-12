package com.forticode.cipherise;

import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.json.JSONObject;

import com.forticode.cipherise_app_sim_int.Application;
import com.mashape.unirest.http.HttpResponse;

/**
 * Unit test for simple App.
 */
public class JavaSDKTest
// extends TestCase
{
    // The URL of the Cipherise Server with a single end-slash at the end.
    String origCipheriseServerURL = null;
    // The URL of the Cipherise Server with 0 to any number of end-slashes at the end.
    String cipheriseServerURL = null;
    // URL to a CS to test version mismatch against
    String oldCipheriseServerURL = null;
    // The URL of the App Simulator.
    String appSimulatorURL = null;

    Service sp = null;
    Client client = null;
    Application app = null;

    public JavaSDKTest() throws IOException {

        // URL to the name to match against, if there is network name changes occurring.
        origCipheriseServerURL = System.getenv("ORIG_CIPHERISE_SERVER_URL");
        assert (!origCipheriseServerURL.isEmpty());

        // URL to the CS testing against.
        cipheriseServerURL = System.getenv("CIPHERISE_SERVER_URL");
        assert (!cipheriseServerURL.isEmpty());

        // URL to a CS to test version mismatch against
        oldCipheriseServerURL = System.getenv("OLD_CIPHERISE_SERVER_URL");
        assert (!oldCipheriseServerURL.isEmpty());

        // URL to the app simulator.
        appSimulatorURL = System.getenv("APP_SIMULATOR_URL");
        assert (!appSimulatorURL.isEmpty());
    }

    @Before
    public void prepWork() throws CipheriseException, IOException {
        // Check and prepare the Cipherise Server connection
        if (this.client == null) {
            this.client = new Client(cipheriseServerURL);
        }

        // Check for and prepare the Service Provider for testing, and session to the
        // server.
        if (this.sp == null) {
            this.sp = this.client.createService("Java SDK Test Service");
        }

        // Check and prepare our Application Simulator
        this.app = new Application(appSimulatorURL);
    }

    // Test successful creation of a client
    @Test
    public void createClientTest() throws CipheriseException, IOException {
        Client myClient = new Client(cipheriseServerURL);
        assert (myClient.getAddress().equals(origCipheriseServerURL));
    }

    // Test unsuccessful creation of a service due to incompatibility of Cipherise
    // Server version
    @Test(expected = CipheriseException.class)
    public void createClientOnLowerVersionCSTest() throws CipheriseException, IOException {
        Client myClient = new Client(oldCipheriseServerURL);
        myClient.createService("Testing 123");
    }

    // Test unsuccessful creation of a service due to bad server address
    @Test(expected = CipheriseException.class)
    public void createClientTestFail() throws CipheriseException, IOException {
        Client myClient = new Client("https://notarealserver.com");
        myClient.createService("Testing 123");
    }

    // Test successful creation of a service
    @Test
    public void createServiceTest() throws CipheriseException, IOException {
        Service sp = client.createService("Testing 123");
        assert (!sp.getId().isEmpty());
    }

    // Test successful serialization and deserialization of a service
    @Test
    public void canSerializeAndDeserializeAService() throws CipheriseException, IOException {
        Service sp = client.createService("Testing 123");
        byte[] serialized = sp.serialize();
        assert (serialized != null && serialized.length != 0);
        Service deserialized = client.deserializeService(serialized);
        assert (sp.equals(deserialized));
    }

    // Test successful deserialization of a pre-versioning service
    @Test
    public void canDeserializeAPreversioningService() throws CipheriseException, IOException {
        Client myClient = new Client(oldCipheriseServerURL);
        myClient.validateServerVersion = false;
        final byte[] SERIALIZED_SERVICE = CryptoUtil.fromHexString(
                "95a84369706853727663b030303030303030303030303030303166c5025f3082025b020100028181009dd37039944022a8c363fd4b8ea0f645b83c216038ef9ba0b1f787706679276de2a963052b4c1f0e13fd4bd14f267eca8c26f04b1440f9d9846c92e1ca1eefb7344ced880b273199653ffa899ee14cefe15b16147b7f0485c2c4787ef17f77316943ede63fb66e38675a36f19f8a885020a98abc8f4ca2705957675c9b1a926f020301000102818044683efe5609ae7c23a49547489cefe1ac4733d83715740924da3b3436d65086ca75ccdb92b6bdc72656e5a3e580b3f82ae33dc7ed1174ba1931ce405b91292936293466d0c75eb8e85e04e3f0d655616baf1da553de93daf83f525fe1822ce93f7e1d5481bd31b0dd1253926e6394509b7802794da4c9e220064c1b07403b31024100fef7e0d5b9f496b11a7cf880e88f8a4791830433607678d408ddc977cbc0afe6583bcb49047a11021d11c5cfddebe38804970b3589bd06b01066e761d1533b830241009e76ee29c104e65ad855b2671bb4351d47c844bd75312cd16e1b25a2a9a5a1771d4b495c67f996c8073d59e441ef5e52a0fa7444b58392884d55662cc1ed3da50240367e562077e10dc0067045508fe3f5e2fbf7ab932b7fc6ad52c3cc467d56ce8185c429db8e48649036145159ef0d7690e0a243b40a9f4ae9a067cdf63b1df5ef0240265309229c05fd58373df299b13f9220f4bd60b299673d39a1717b56adc4db1a1dc1998a79b3095e7331c94dc50c89395ea973f93215121958eab07d5ea16be902400c5d0521a384653ec3e92ad07ab97a616be3d43b56e8e9b04c2b3345d915ca3f27867968a2e0510f9f14eb3f78ea776c72a0226a88e1baae18256d7c1ad9a894c420e94e8952371060c08ca4743c7fa06295188191f82e3c8cd38afe66f543535eadc0");
        Service service = myClient.deserializeService(SERIALIZED_SERVICE);
        assert (service.getId().equals("000000000000001f"));
        assert (Arrays.equals(service.sign(CryptoUtil.fromHexString("00")), CryptoUtil.fromHexString(
                "953608e19bdac8cc5d6306d6e0d5558c930b77636ce32806d8cf0eddbe0ef95b89176de0a651191f079ad321be6b6f4374f6a0e7b8210dc8a65c24c2dc6de403931d779b6aae3f5e9d3cf79fa2d7ba939c44789ca7177f6944e94915b3c101e88f7e891a2a384828dc2df2342e48023314c5b13c8a6e11acf1cefe035180fdeb")));
    }

    private void appSimScan(String url, Function<JSONObject, Boolean> func) {

        new Thread(() -> {
            try {
                HttpResponse<String> ret = this.app.scan(url);

                if (func != null) {
                    JSONObject auth = new JSONObject(ret.getBody()).getJSONObject("authentication");
                    func.apply(auth);
                }

            } catch (Exception e) {
                // TODO Does this lock up the test??
            }

        }).start();
    }

    private void appSimAuthenticate(int responseDelayTimeInSeconds, Function<JSONObject, Boolean> func) {

        new Thread(() -> {
            try {
                // Sleep for a bit - to simulate human response time
                Thread.sleep(responseDelayTimeInSeconds * 1000);

                JSONArray auths = app.checkPushedAuths();
                for (int i = 0; i < auths.length(); i++) {
                    func.apply(auths.getJSONObject(i));
                }
            } catch (Exception e) {
                // TODO Does this lock up the test??
            }

        }).start();
    }

    // Test enrolment with long poll
    @Test
    public void enrolAppToServiceLongPollTest() throws CipheriseException {
        // Start an enrolment for this test runner - expect QR code URL
        Enrolment rs = this.sp.enrolUser("Yo Gabba Test User Long Poll");

        // Simulate scanning of a WaveCode by passing this URL to the app sim
        this.appSimScan(rs.getWaveCodeUrl(), null);

        // Wait for the CS to complete binding
        rs.validate();

        // Accept the enrolment
        rs.confirm(true);
    }

    public Boolean successAppAuth(JSONObject auth) {
        try {
            app.authenticate(auth, "true");
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public Boolean cancelAppAuth(JSONObject auth) {
        try {
            app.authenticate(auth, "cancelled");
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public Boolean reportAppAuth(JSONObject auth) {
        try {
            app.authenticate(auth, "reported");
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public Boolean failAppAuth(JSONObject auth) {
        try {
            app.authenticate(auth, "false");
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public void waveAuthTest(Function<JSONObject, Boolean> appAuth, Authenticated authenticated)
            throws CipheriseException {
        final String username = "Yo Gabba Test Wave Auth";

        // Start an enrolment for this test runner - expect QR code URL
        Enrolment rs = this.sp.enrolUser(username);

        // Simulate scanning of a QR by passing this URL to the app sim
        this.appSimScan(rs.getWaveCodeUrl(), null);

        // Wait for the CS to complete binding
        rs.validate();

        // Accept the enrolment
        rs.confirm(true);

        // Create an Auth Session
        Authentication as = this.sp.waveAuthenticate("gabba", "gabba", null, AuthenticationLevel.Notification);

        // Client side scan the given QR code
        this.appSimScan(as.getWaveCodeUrl(), appAuth);

        // SP side, wait for the client and assert validation.
        AuthenticationResult result = as.authenticate();
        assert (result.username.equals(username));
        assert (result.authenticated.equals(authenticated));
    }

    // Test successful blocking wave auth
    @Test
    public void waveAuthTestSuccess() throws CipheriseException {
        this.waveAuthTest(this::successAppAuth, Authenticated.Success);
    }

    // Test cancelled blocking wave auth
    @Test
    public void waveAuthTestCancel() throws CipheriseException {
        this.waveAuthTest(this::cancelAppAuth, Authenticated.Cancel);
    }

    // Test reported blocking wave auth
    @Test
    public void waveAuthTestReport() throws CipheriseException {
        this.waveAuthTest(this::reportAppAuth, Authenticated.Report);
    }

    // Test failed blocking wave auth
    @Test
    public void waveAuthTestFail() throws CipheriseException {
        this.waveAuthTest(this::failAppAuth, Authenticated.Failure);
    }

    @Test
    public void waveAuthTestWithPayload() throws CipheriseException {
        final String username = "Yo Gabba Test Wave Auth";
        final Map<String, String> payload1 = new HashMap<>();
        payload1.put("hello", "world");
        final Map<String, String> payload2 = new HashMap<>();
        payload2.put("think", "different");
        final Map<String, String> payloadBoth = new HashMap<>();
        payloadBoth.putAll(payload1);
        payloadBoth.putAll(payload2);

        // Start an enrolment for this test runner - expect QR code URL
        Enrolment rs = this.sp.enrolUser(username);

        // Simulate scanning of a QR by passing this URL to the app sim
        this.appSimScan(rs.getWaveCodeUrl(), null);

        // Wait for the CS to complete binding
        rs.validate();

        // Accept the enrolment with a payload.
        rs.confirm(true, new PayloadRequestBuilder().withSet(payload1).build());

        // Create an Auth Session
        Authentication as = this.sp.waveAuthenticate("gabba", "gabba", null, AuthenticationLevel.Notification);

        // Client side scan the given QR code
        this.appSimScan(as.getWaveCodeUrl(), this::successAppAuth);

        // SP side, wait for the client and assert validation.
        AuthenticationResult result = as.authenticate(true, new PayloadRequestBuilder()
                .withGet(new ArrayList<String>(payload1.keySet())).withSet(payload2).build());
        assert (result.username.equals(username));
        assert (result.authenticated.equals(Authenticated.Success));
        assert (result.payload != null);
        assert (result.payload.set);
        assert (result.payload.get.equals(payload1));

        // Do another quick authentication to check all values are present.
        as = this.sp.waveAuthenticate("gabba", "gabba", null, AuthenticationLevel.Notification);

        // Client side scan the given QR code
        this.appSimScan(as.getWaveCodeUrl(), this::successAppAuth);

        // SP side, wait for the client and assert validation.
        result = as.authenticate(true,
                new PayloadRequestBuilder().withGet(new ArrayList<String>(payloadBoth.keySet())).build());
        assert (result.username.equals(username));
        assert (result.authenticated.equals(Authenticated.Success));
        assert (result.payload != null);
        assert (!result.payload.set);
        assert (result.payload.get.equals(payloadBoth));

        // Do another authentication to check that large payloads are rejected.
        as = this.sp.waveAuthenticate("gabba", "gabba", null, AuthenticationLevel.Notification);

        // Client side scan the given QR code
        this.appSimScan(as.getWaveCodeUrl(), this::successAppAuth);

        // SP side, wait for the client and assert validation.
        ServerInformation si = this.client.serverInformation();
        byte[] data = CryptoUtil.generateRandomBytes(si.maxPayloadSize);

        final Map<String, String> payloadLarge = new HashMap<>();
        payloadLarge.put("hello", CryptoUtil.toHexString(data));
        try {
            result = as.authenticate(true,
                    new PayloadRequestBuilder().withSet(payloadLarge).build());
            assert(false);
        } catch (CipheriseException e) {
            assert(true);
        }
    }

    public void pushAuthTest(Function<JSONObject, Boolean> appAuth, Authenticated authenticated)
            throws CipheriseException {
        final String username = "Yo Gabba Test Push Auth";

        // Start an enrolment for this test runner - expect QR code URL
        Enrolment rs = this.sp.enrolUser(username);

        // Simulate scanning of a QR by passing this URL to the app sim
        this.appSimScan(rs.getWaveCodeUrl(), null);

        // Wait for the CS to complete binding
        rs.validate();

        // Accept the enrolment
        rs.confirm(true);

        // Fetch the user devices
        List<Device> devices = this.sp.getUserDevices(username);

        // Create an Auth Session
        Authentication as = this.sp.pushAuthenticate(username, devices.get(0), "yo", "gabba", "gabba", AuthenticationLevel.Notification);

        // Client side approve the auth
        this.appSimAuthenticate(10, appAuth);

        // SP side, wait for the client and assert validation.
        AuthenticationResult result = as.authenticate();
        assert (result.username.equals(username));
        assert (result.authenticated.equals(authenticated));
    }

    // Test successful blocking push auth
    @Test
    public void pushAuthTestSuccess() throws CipheriseException {
        this.pushAuthTest(this::successAppAuth, Authenticated.Success);
    }

    // Test cancelled blocking push auth
    @Test
    public void pushAuthTestCancel() throws CipheriseException {
        this.pushAuthTest(this::cancelAppAuth, Authenticated.Cancel);
    }

    // Test reported blocking push auth
    @Test
    public void pushAuthTestReport() throws CipheriseException {
        this.pushAuthTest(this::reportAppAuth, Authenticated.Report);
    }

    // Test failed blocking push auth
    @Test
    public void pushAuthTestFail() throws CipheriseException {
        this.pushAuthTest(this::failAppAuth, Authenticated.Failure);
    }

    @Test
    public void canSerializeAndDeserializeAnEnrolment() throws CipheriseException {
        final String username = "Enrolment Serializer";
        Enrolment enrolment = this.sp.enrolUser(username);

        // Serialize and deserialize the enrolment, then check if it works.
        byte[] serializedEnrolment = enrolment.serialize();
        assert (serializedEnrolment != null);

        Enrolment deserializedEnrolment = this.sp.deserializeEnrolment(serializedEnrolment);
        assert (deserializedEnrolment != null);

        assert (enrolment.equals(deserializedEnrolment));

        // Simulate scanning of a QR by passing this URL to the app sim
        this.appSimScan(enrolment.getWaveCodeUrl(), null);

        // Wait for the CS to complete binding
        enrolment.validate();

        // Try serialization/deserialization again, now that the state has mutated.
        serializedEnrolment = enrolment.serialize();
        assert (serializedEnrolment != null);

        deserializedEnrolment = this.sp.deserializeEnrolment(serializedEnrolment);
        assert (deserializedEnrolment != null);

        assert (enrolment.equals(deserializedEnrolment));

        // Accept the enrolment
        enrolment.confirm(false);
    }

    @Test
    public void canSerializeAndDeserializeAWaveAuthentication() throws CipheriseException {
        Authentication authentication = this.sp.waveAuthenticate("authenticationMessage", "brandingMessage", null, AuthenticationLevel.Notification);

        // Serialize, deserialize and check for equality.
        byte[] serializedAuthentication = authentication.serialize();
        assert (serializedAuthentication != null);

        Authentication deserializedAuthentication = this.sp.deserializeAuthentication(serializedAuthentication);
        assert (deserializedAuthentication != null);

        assert (authentication.equals(deserializedAuthentication));
    }

    @Test
    public void canSerializeAndDeserializeAPushAuthentication() throws CipheriseException {
        final String username = "Push Authentication Serializer";

        // Start an enrolment for this test runner - expect QR code URL
        Enrolment rs = this.sp.enrolUser(username);

        // Simulate scanning of a QR by passing this URL to the app sim
        this.appSimScan(rs.getWaveCodeUrl(), null);

        // Wait for the CS to complete binding
        rs.validate();

        // Accept the enrolment
        rs.confirm(true);

        // Fetch the user devices
        List<Device> devices = this.sp.getUserDevices(username);

        // Create an Auth Session
        Authentication authentication = this.sp.pushAuthenticate(username, devices.get(0), "yo", "gabba", "gabba", AuthenticationLevel.Notification);

        // Serialize, deserialize and check for equality.
        byte[] serializedAuthentication = authentication.serialize();
        assert (serializedAuthentication != null);

        Authentication deserializedAuthentication = this.sp.deserializeAuthentication(serializedAuthentication);
        assert (deserializedAuthentication != null);

        assert (authentication.equals(deserializedAuthentication));
    }
}
