package sample.neg;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class HttpCaller {

    int post(String endpoint) throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        String encrypt = "encrypt";
        String key = "demo-key";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint + "/keys/" + key))
                .header("X-Operation", encrypt)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode();
    }
}