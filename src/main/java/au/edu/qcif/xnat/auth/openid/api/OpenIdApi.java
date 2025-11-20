package au.edu.qcif.xnat.auth.openid.api;

import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.preferences.OpenIdPreferences;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.nrg.framework.annotations.XapiRestController;
import org.nrg.xapi.exceptions.NotFoundException;
import org.nrg.xapi.rest.AbstractXapiRestController;
import org.nrg.xapi.rest.XapiRequestMapping;
import org.nrg.xdat.security.services.RoleHolder;
import org.nrg.xdat.security.services.UserManagementServiceI;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import static org.nrg.xdat.security.helpers.AccessLevel.Admin;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

@XapiRestController
@RequestMapping("/openid")
@Slf4j
public class OpenIdApi extends AbstractXapiRestController {

    private static final String PRIVACY_POLICY_FILE_PROPERTY_NAME = "privacyPolicy";
    private static final String TOS_FILE_PROPERTY_NAME = "tos";
    private static final String HTML_CHARSET_UTF_8_MEDIA_TYPE = MediaType.TEXT_HTML_VALUE + ";charset=UTF-8";

    private final KeystoreService keystoreService;
    private final Path xnatHome;
    private final OpenIdAuthPlugin openIdAuthPlugin;
    private final OpenIdPreferences openIdPreferences;

    public OpenIdApi(final UserManagementServiceI userManagementService,
                     final RoleHolder roleHolder,
                     final KeystoreService keystoreService,
                     final Path xnatHome,
                     final OpenIdAuthPlugin openIdAuthPlugin,
                     final OpenIdPreferences openIdPreferences) {
        super(userManagementService, roleHolder);
        this.keystoreService = keystoreService;
        this.xnatHome = xnatHome;
        this.openIdAuthPlugin = openIdAuthPlugin;
        this.openIdPreferences = openIdPreferences;
    }

    @XapiRequestMapping(value = ".well-known/jwks.json", produces = APPLICATION_JSON_VALUE, method = GET)
    public Map<String, Object> getPublicKey() throws NotFoundException {
        return keystoreService.getJwks().toJSONObject();
    }

    @XapiRequestMapping(value = "legal/privacy-policy", produces = HTML_CHARSET_UTF_8_MEDIA_TYPE)
    public String privacyPolicy() throws IOException, NotFoundException {
        final Optional<Path> document = getDocumentPathFromFilenameProperty(PRIVACY_POLICY_FILE_PROPERTY_NAME);
        if (document.isPresent()) {
            return new String(Files.readAllBytes(document.get()), StandardCharsets.UTF_8);
        }
        throw new NotFoundException("Unable to find privacy policy");
    }

    @XapiRequestMapping(value = "legal/terms-of-service", produces = HTML_CHARSET_UTF_8_MEDIA_TYPE)
    public String termsOfService() throws IOException, NotFoundException {
        final Optional<Path> tosDocumentPath = getDocumentPathFromFilenameProperty(TOS_FILE_PROPERTY_NAME);
        if (tosDocumentPath.isPresent()) {
            return new String(Files.readAllBytes(tosDocumentPath.get()), StandardCharsets.UTF_8);
        }
        throw new NotFoundException("Unable to find terms of service");
    }

    /**
     * Check if an encryption key exists for an algorithm.
     * Returns true if a key exists for the specified algorithm, false otherwise.
     */
    @XapiRequestMapping(value = "/keys/{algorithm}", produces = APPLICATION_JSON_VALUE, method = GET, restrictTo = Admin)
    public boolean getEncryptionKeyStatus(@PathVariable final String algorithm) {
        return openIdPreferences.hasJwk(algorithm);
    }

    private Optional<Path> getDocumentPathFromFilenameProperty(final String property) {
        final String documentFileName = openIdAuthPlugin.getProperty(property);
        if (StringUtils.isBlank(documentFileName)) {
            return Optional.empty();
        }
        final Path documentPathPath = xnatHome.resolve(documentFileName);
        if (!Files.exists(documentPathPath) || !Files.isRegularFile(documentPathPath) || !Files.isReadable(documentPathPath)) {
            return Optional.empty();
        }

        return Optional.of(documentPathPath);
    }
}
