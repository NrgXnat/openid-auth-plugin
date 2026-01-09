package au.edu.qcif.xnat.auth.openid.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import org.nrg.xapi.exceptions.NotFoundException;

import java.security.PrivateKey;

public interface KeystoreService {
    JWKSet getJwks() throws NotFoundException;

    PrivateKey getEncryptionPrivateKey(String providerId) throws JOSEException, NotFoundException;
}
