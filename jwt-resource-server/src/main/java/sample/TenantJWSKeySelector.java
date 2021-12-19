package sample;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TenantJWSKeySelector implements JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

    //	private final TenantRepository tenants; // (1)
    private final Map<String, JWSKeySelector<SecurityContext>> selectors = new ConcurrentHashMap<>(); // (2)

    //	public TenantJWSKeySelector(TenantRepository tenants) {
    //		this.tenants = tenants;
    //	}

    @Override
    public List<? extends Key> selectKeys(JWSHeader jwsHeader, JWTClaimsSet jwtClaimsSet, SecurityContext securityContext) throws KeySourceException {
        JWSKeySelector<SecurityContext> keySelector = this.selectors.computeIfAbsent(toTenant(jwtClaimsSet), this::fromTenant);
        return keySelector.selectJWSKeys(jwsHeader, securityContext);
    }

    private String toTenant(JWTClaimsSet claimSet) {
        String issuer = (String) claimSet.getClaim("iss");
        if (issuer == null) {
            return "Legacy";
        } else if (issuer.equals("HT-IOAUTH")) {
            return "HT-IOAUTH";
        } else if (issuer.equals("OAUTH")) {
            return "OAUTH";
        }
        throw new RuntimeException("JWT issued by unknown issuer : " + issuer);
    }

    private JWSKeySelector<SecurityContext> fromTenant(String tenant) {
        switch (tenant) {
            case "Legacy":
                return getSymmetricKeySelector();
            case "HT-IOAUTH":
            case "OAUTH":
                return getAsymmetricKeySelector(tenant);
        }
        throw new RuntimeException("Unknown tenant : " + tenant);
    }

    private JWSKeySelector<SecurityContext> getSymmetricKeySelector() {
        byte[] key = "123".getBytes();
        byte[] paddedKey = key.length < 32 ? Arrays.copyOf(key, 32) : key;

        JWKSource keySource = new ImmutableSecret(paddedKey);
        return new JWSVerificationKeySelector<SecurityContext>(JWSAlgorithm.parse(JwsAlgorithms.HS256), keySource);
    }

    private JWSKeySelector<SecurityContext> getAsymmetricKeySelector(String tenant) {
        RSAPublicKey publicKey = null;
        try {
            publicKey = getPublicKey(tenant);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        RSAKey rsaKey = new RSAKey.Builder(publicKey).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        JWKSource jwkSource = new ImmutableJWKSet<>(jwkSet);
        return new JWSVerificationKeySelector<>(JWSAlgorithm.parse(JwsAlgorithms.RS512), jwkSource);
    }

    private RSAPublicKey getPublicKey(String tenant) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyFile;
        switch (tenant) {
            case "HT-IOAUTH":
                publicKeyFile = "public_htioauth.pem";
                break;
            case "OAUTH":
                publicKeyFile = "public_oauth.pem";
                break;
            default:
                throw new RuntimeException("Unknown tenant : " + tenant);
        }

        try (InputStream is = getClass().getClassLoader().getResourceAsStream(publicKeyFile)) {
            String key = new String(is.readAllBytes());

            String publicKeyPEM = key
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");

            byte[] encoded = Base64.decodeBase64(publicKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }
    }
}