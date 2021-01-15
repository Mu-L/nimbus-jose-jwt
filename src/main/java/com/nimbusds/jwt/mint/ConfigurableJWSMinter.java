package com.nimbusds.jwt.mint;

import com.nimbusds.jose.proc.SecurityContext;

public interface ConfigurableJWSMinter<C extends SecurityContext>
	extends JWSMinter<C>, JWSMinterConfiguration<C> {
}
