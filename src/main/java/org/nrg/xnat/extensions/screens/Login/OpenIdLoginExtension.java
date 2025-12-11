package org.nrg.xnat.extensions.screens.Login;

import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.OPENID_ERROR_MESSAGE;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.turbine.util.RunData;
import org.nrg.framework.utilities.Reflection;

import java.util.Map;

/**
 * Login screen extension that displays custom OpenID authentication error messages.
 * This extension is automatically loaded by XNAT's dynamic variable loading mechanism
 * when classes implementing {@link Reflection.InjectableI} are found in the
 * org.nrg.xnat.extensions.screens.Login package.
 */
@Slf4j
public class OpenIdLoginExtension implements Reflection.InjectableI {

    @Override
    public void execute(Map<String, Object> params) {
        final RunData data = (RunData) params.get("data");
        if (data == null) {
            return;
        }

        try {
            final String errorMessage = (String) data.getSession().getAttribute(OPENID_ERROR_MESSAGE);
            if (StringUtils.isNotBlank(errorMessage)) {
                log.debug("Setting OpenID error message on login page: {}", errorMessage);
                data.setMessage(errorMessage);
                // Remove the attribute so it doesn't persist across page loads
                data.getSession().removeAttribute(OPENID_ERROR_MESSAGE);
            }
        } catch (Exception e) {
            log.error("Error processing OpenID login extension", e);
        }
    }
}
