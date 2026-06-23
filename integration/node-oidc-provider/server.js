// node-oidc-provider test oracle for huskarl integration tests.
//
// A spec-compliant OIDC provider used as a conformant reference. Clients are
// created at runtime via RFC 7591 dynamic registration (no static clients), and
// login is driven headlessly through the built-in `devInteractions` UI (a fixed
// identity — any username, any password). Scoped to the authorization-code
// family: auth_code, PAR (RFC 9126), and JAR (RFC 9101).

import { createServer } from 'node:http';
import Provider from 'oidc-provider';
import { exportJWK, generateKeyPair } from 'jose';

const PORT = Number(process.env.PORT ?? 3000);
const ISSUER = process.env.ISSUER ?? `http://127.0.0.1:${PORT}`;

// Fresh signing keys on each start — this is an ephemeral test oracle, so
// rotating keys are fine (tests fetch the JWKS fresh). Both RS256 (the ecosystem
// default for `id_token_signed_response_alg`) and ES256 are offered so clients
// can register without negotiating an algorithm.
const { privateKey: rsaKey } = await generateKeyPair('RS256', { extractable: true });
const rsaJwk = { ...(await exportJWK(rsaKey)), use: 'sig', alg: 'RS256', kid: 'rsa-sig' };
const { privateKey: ecKey } = await generateKeyPair('ES256', { extractable: true });
const ecJwk = { ...(await exportJWK(ecKey)), use: 'sig', alg: 'ES256', kid: 'ec-sig' };

const configuration = {
  jwks: { keys: [rsaJwk, ecJwk] },

  // Static cookie key — fine for an ephemeral test oracle; silences the
  // tamper-detection warning and keeps the interaction session stable.
  cookies: { keys: ['huskarl-integration-test-cookie-key'] },

  // No static clients — every test registers its own via RFC 7591.
  clients: [],
  clientDefaults: {
    grant_types: ['authorization_code'],
    response_types: ['code'],
  },

  // PKCE always required (RFC 9700 best practice; matches huskarl's default).
  pkce: { required: () => true },

  // Fixed test identity — devInteractions accepts any username as the account id.
  findAccount: async (_ctx, id) => ({
    accountId: id,
    async claims() {
      return { sub: id };
    },
  }),

  features: {
    // Built-in login/consent UI so the auth-code flow can be driven headlessly.
    devInteractions: { enabled: true },
    // RFC 7591 open dynamic client registration (no initial access token).
    registration: { enabled: true },
    // RFC 9126 pushed authorization requests (optional, not required).
    pushedAuthorizationRequests: { enabled: true, requirePushedAuthorizationRequests: false },
    // RFC 9101 JWT-secured authorization requests via the inline `request` param.
    requestObjects: { enabled: true, request: true, requestUri: false },
  },
};

const provider = new Provider(ISSUER, configuration);

createServer(provider.callback()).listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`node-oidc-provider listening on ${ISSUER}`);
});
