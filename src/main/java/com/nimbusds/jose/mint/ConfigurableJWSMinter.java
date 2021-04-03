package com.nimbusds.jose.mint;

import com.nimbusds.jose.proc.SecurityContext;


/**
 * Configurable JSON Web Signature (JWS) minter.
 */
public interface ConfigurableJWSMinter<C extends SecurityContext>
	extends JWSMinter<C>, JWSMinterConfiguration<C> {
}
