package com.forticode.cipherise;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.nio.reactor.IOReactorException;
import org.json.JSONObject;

class WebClient {
    final private String address;
    final private Boolean logging;

    WebClient(String address) {
        this.address = address;
        this.logging = System.getenv("CIPHERISE_SDK_LOG_HTTP") != null;

        // Create a new connection manager to raise the concurrent connection limit
        final int MaxTotal = 1000000;
        final int MaxPerRoute = 1000000;
        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager();
        connManager.setMaxTotal(MaxTotal);
        connManager.setDefaultMaxPerRoute(MaxPerRoute);

        // Create a new async connection manager to raise the concurrent connection
        // limit for async calls
        PoolingNHttpClientConnectionManager asyncConnManager;
        try {
            DefaultConnectingIOReactor reactor = new DefaultConnectingIOReactor();
            asyncConnManager = new PoolingNHttpClientConnectionManager(reactor);
            asyncConnManager.setMaxTotal(MaxTotal);
            asyncConnManager.setDefaultMaxPerRoute(MaxPerRoute);
        } catch (IOReactorException e) {
            connManager.close();
            throw new RuntimeException(e);
        }

        // Create a new request configuration to raise the time until the client times
        // out
        RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(10000).setSocketTimeout(0).build();

        // Use custom HTTP/async HTTP clients to disable automatic retries and to use
        // the connection manager/request config
        Unirest.setHttpClient(HttpClientBuilder.create().disableAutomaticRetries()
                .setDefaultRequestConfig(requestConfig).setConnectionManager(connManager).build());
        Unirest.setAsyncHttpClient(HttpAsyncClientBuilder.create().setDefaultRequestConfig(requestConfig)
                .setConnectionManager(asyncConnManager).build());
    }

    JSONObject processResponse(String method, String path, HttpResponse<String> response) throws CipheriseException {
        if (this.logging) {
            System.out.println(method + " " + path + ": " + response.getBody());
        }

        // Explicitly throw a timeout exception if the response has timed out, is a
        // proxy error, or is a proxy timeout.
        // We check for proxy error as a reverse proxy may end up terminating the
        // response before the server itself can
        // respond, and it may return 502 instead of the more correct 504.
        int status = response.getStatus();
        if (status == 408 || status == 502 || status == 504) {
            throw new CipheriseException(new TimeoutException("Timeout during " + method + " " + path));
        }

        JSONObject obj = new JSONObject(response.getBody());
        if (obj.has("error") && obj.getBoolean("error")) {
            throw new CipheriseException(obj.getString("error_message"), obj.getInt("error_code"));
        }

        return obj;
    }

    JSONObject get(String path, String sessionId) throws CipheriseException {
        if (path.startsWith("/")) {
            path = this.address + path.substring(1);
        }

        if (this.logging) {
            System.out.println("GET " + path);
        }

        HttpResponse<String> response;
        try {
            // @formatter:off
            response = Unirest
                .get(path)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("SessionId", sessionId)
                .asString();
            // @formatter:on
        } catch (UnirestException e) {
            if (e.getCause() instanceof org.apache.http.NoHttpResponseException) {
                throw new CipheriseException(new TimeoutException("Timeout during GET " + path));
            }
            throw new CipheriseException(e);
        }

        return this.processResponse("GET", path, response);
    }

    JSONObject post(String path, JSONObject body, String sessionId) throws CipheriseException {
        if (path.startsWith("/")) {
            path = this.address + path.substring(1);
        }

        if (this.logging) {
            System.out.println("POST " + path + ": " + body.toString());
        }

        HttpResponse<String> response;
        try {
            // @formatter:off
            if (body == null)
                 response = Unirest
                    .post(path)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .header("SessionId", sessionId)                    
                    .asString();
            else
                 response = Unirest
                    .post(path)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .header("SessionId", sessionId)
                    .body(body)
                    .asString();
            // @formatter:on
        } catch (UnirestException e) {
            if (e.getCause() instanceof org.apache.http.NoHttpResponseException) {
                throw new CipheriseException(new TimeoutException("Timeout during GET " + path));
            }
            throw new CipheriseException(e);
        }

        return this.processResponse("POST", path, response);
    }
}