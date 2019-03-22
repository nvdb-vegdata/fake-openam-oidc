package no.vegvesen.fakeopenam;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Path("/openam")
public class FakeOpenAM {

    private final RSAKey rsaJWKemployee;
    private final RSAKey rsaJWKserviceAccount;

    @ConfigProperty(name = "fake.clientId")
    private String clientId;

    @ConfigProperty(name = "fake.clientSecret")
    private String clientSecret;

    @ConfigProperty(name = "fake.issuerBase")
    private String issuerBase;

    public FakeOpenAM() throws JOSEException {
        rsaJWKemployee = new RSAKeyGenerator(2048)
                .keyID("nvdbapi-v3-employee")
                .generate();
        rsaJWKserviceAccount = new RSAKeyGenerator(2048)
                .keyID("nvdbapi-v3-serviceAccount")
                .generate();
    }

    @POST
    @Consumes("application/x-www-form-urlencoded")
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/oauth2/Employees/access_token")
    public Response employeeAccessToken(@Context HttpHeaders headers, @FormParam("username") String username) throws JOSEException {
        if(notValidAuth(headers) || username == null || username.isEmpty()) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        return getResponse(username, this.rsaJWKemployee, issuerBase + "/oauth2/Employees");
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/oauth2/Employees/connect/jwk_uri")
    public Response employeeJWK(@Context HttpHeaders headers) {
        return Response.ok(
                toJWK(rsaJWKemployee), MediaType.APPLICATION_JSON_TYPE
        ).build();
    }

    @POST
    @Consumes("application/x-www-form-urlencoded")
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/oauth2/WSClients_Int/access_token")
    public Response serviceAccountAccessToken(@Context HttpHeaders headers, @FormParam("username") String username) throws JOSEException {
        if(notValidAuth(headers)) return Response.status(Response.Status.UNAUTHORIZED).build();

        return getResponse(username, this.rsaJWKserviceAccount, issuerBase + "/oauth2/WSClients_Int");

    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/oauth2/WSClients_Int/connect/jwk_uri")
    public Response serviceAccountJWK(@Context HttpHeaders headers) {
        return Response.ok(
                toJWK(rsaJWKserviceAccount), MediaType.APPLICATION_JSON_TYPE
        ).build();
    }

    private Response getResponse(String username, RSAKey rsaJWKemployee, String issuer) throws JOSEException {
        String jwt = jwt(username, rsaJWKemployee, issuer);
        Map<String, String> response = new HashMap<>();
        response.put("id_token", jwt);
        response.put("access_token", jwt);
        response.put("refresh_token", jwt);
        response.put("token_type", "bearer");
        return Response
                .ok(response, MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    private String jwt(String username, RSAKey rsaJWK, String issuer) throws JOSEException {
        JWSSigner signer = new RSASSASigner(rsaJWK);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),
                new JWTClaimsSet.Builder()
                        .claim("iss", issuer)
                        .claim("sub", username)
                        .claim("uid", username)
                        .claim("aud", username)
                        .claim("exp", Instant.now().plusSeconds(60).getEpochSecond())
                        .claim("iat", Instant.now().getEpochSecond())
                        .claim("svvroles", new String[]{})
                        .build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private static String toJWK(RSAKey rsaJWK) {
        RSAKey publicJWK = rsaJWK.toPublicJWK();

        JSONObject keys = new JSONObject()
                .appendField("keys",
                        new JSONArray()
                                .appendElement(
                                        publicJWK.toJSONObject()));
        return keys.toJSONString();
    }

    private boolean notValidAuth(HttpHeaders headers) {
        String authorization = headers.getHeaderString("Authorization");
        if(authorization == null || authorization.isEmpty()) return true;

        String basicAuth = authorization.replace("Basic ", "");
        try {
            String expectedWithUrlEncoding = Base64.getEncoder()
                    .encodeToString((URLEncoder.encode(clientId, "UTF-8") + ":" + URLEncoder.encode(clientSecret, "UTF-8")).getBytes());
            if(basicAuth.equals(expectedWithUrlEncoding)) {
                return false;
            }
            String expectedNoUrlEncoding = Base64.getEncoder()
                    .encodeToString((clientId + ":" + clientSecret).getBytes());
            if(basicAuth.equals(expectedNoUrlEncoding)) {
                return false;
            }
        } catch (UnsupportedEncodingException e) {
            return true;
        }
        return false;
    }
}
