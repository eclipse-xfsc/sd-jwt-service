
const express = require('express');
const { digest, generateSalt } = require('@sd-jwt/crypto-nodejs');
const { decodeSdJwt, getClaims } = require('@sd-jwt/decode');
const crypto = require('crypto');
const axios = require('axios');
const { SDJwtVcInstance } = require('@sd-jwt/sd-jwt-vc');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();

app.use(express.json({ limit: '1mb' }));

app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(
    swaggerJsdoc({
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'SD-JWT Service',
          version: '1.0.0'
        }
      },
      apis: ['./server.js']
    })
  )
);

// ------------------------------------------------------------
// Logging
// ------------------------------------------------------------

function logVerification(stage, fields = {}) {
  console.info(JSON.stringify({
    event: 'sdjwt.verify',
    stage,
    ...fields
  }));
}

function describePresentation(sdjwt) {
  const parts = sdjwt.split('~');
  const last = parts.length > 1 ? parts[parts.length - 1] : '';

  const hasPotentialKbJwt =
    last !== '' && last.split('.').length === 3;

  return {
    segmentCount: parts.length,
    disclosureCount: Math.max(
      0,
      parts.length - (hasPotentialKbJwt ? 2 : 1)
    ),
    hasPotentialKbJwt,
    trailingTilde: sdjwt.endsWith('~')
  };
}

// ------------------------------------------------------------
// DID Resolution
// ------------------------------------------------------------

async function fetchDIDDocument(did) {
  const response = await axios.get(
    `${process.env.DID_RESOLVER}/1.0/identifiers/${encodeURIComponent(did)}`
  );

  return response.data?.didDocument ?? response.data;
}

function resolveDidJwk(kid) {
  const did = kid.split('#')[0];

  if (!did.startsWith('did:jwk:')) {
    throw new Error('Unsupported DID method');
  }

  const encoded = did.slice('did:jwk:'.length);

  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error('Invalid did:jwk identifier');
  }

  const jwk = JSON.parse(
    Buffer.from(encoded, 'base64url').toString('utf8')
  );

  if (!jwk || typeof jwk !== 'object' || !jwk.kty) {
    throw new Error('Invalid did:jwk public key');
  }

  if (
    jwk.d ||
    jwk.p ||
    jwk.q ||
    jwk.dp ||
    jwk.dq ||
    jwk.qi ||
    jwk.k
  ) {
    throw new Error('Private key material in did:jwk');
  }

  return jwk;
}

async function resolveHolderJwk(cnf) {
  if (cnf?.jwk) {
    const jwk = typeof cnf.jwk === 'string'
      ? JSON.parse(cnf.jwk)
      : cnf.jwk;

    if (!jwk || typeof jwk !== 'object') {
      throw new Error('Invalid cnf.jwk');
    }

    return jwk;
  }

  if (typeof cnf?.kid === 'string') {
    const did = cnf.kid.split('#')[0];

    if (did.startsWith('did:jwk:')) {
      return resolveDidJwk(cnf.kid);
    }

    if (!did.startsWith('did:')) {
      throw new Error('Unsupported cnf.kid');
    }

    const document = await fetchDIDDocument(did);

    const method = document.verificationMethod?.find(
      m =>
        m.id === cnf.kid ||
        m.id === cnf.kid.slice(did.length)
    );

    if (!method?.publicKeyJwk) {
      throw new Error('Holder verification method not found');
    }

    return method.publicKeyJwk;
  }

  throw new Error(
    'Missing holder confirmation key (cnf.jwk/cnf.kid)'
  );
}

// ------------------------------------------------------------
// Issuer Signature Verification
// ------------------------------------------------------------

function createVerifier() {
  return {
    verifier: async (data, sig) => {
      try {
        const [encodedHeader, encodedPayload] = data.split('.');

        if (!encodedHeader || !encodedPayload) {
          throw new Error('Invalid JWT signing input');
        }

        const header = JSON.parse(
          Buffer.from(encodedHeader, 'base64url').toString('utf8')
        );

        const payload = JSON.parse(
          Buffer.from(encodedPayload, 'base64url').toString('utf8')
        );

        let jwk = header.jwk;

        if (!jwk && header.kid) {
          const kid = header.kid;

          const did = kid.startsWith('did:')
            ? kid.split('#')[0]
            : kid.startsWith('#')
              ? payload.iss
              : null;

          if (!did || !did.startsWith('did:')) {
            throw new Error('Unsupported kid');
          }

          const document = await fetchDIDDocument(did);

          const fullKid = kid.startsWith('#')
            ? did + kid
            : kid;

          const fragment = fullKid.includes('#')
            ? fullKid.slice(fullKid.indexOf('#'))
            : null;

          const method = document.verificationMethod?.find(
            m =>
              m.id === fullKid ||
              (fragment && m.id === fragment)
          );

          if (!method?.publicKeyJwk) {
            throw new Error(
              `Verification method not found: ${fullKid}`
            );
          }

          jwk = method.publicKeyJwk;
        }

        if (!jwk) {
          throw new Error('Missing verification key');
        }

        return crypto.verify(
          null,
          Buffer.from(data),
          {
            key: jwk,
            format: 'jwk',
            dsaEncoding: 'ieee-p1363'
          },
          Buffer.from(sig, 'base64url')
        );
      } catch (error) {
        console.error(
          'Issuer signature verification failed:',
          error.message
        );

        return false;
      }
    }
  };
}

// ------------------------------------------------------------
// External Signer
// ------------------------------------------------------------

async function signerFunc(keyMetadata, data) {
  try {
    const response = await axios.post(
      process.env.SIGNER_SIGN_URL,
      {
        namespace: keyMetadata.namespace,
        group: keyMetadata.group,
        key: keyMetadata.key,
        data: Buffer.from(data).toString('base64')
      },
      {
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );

    if (typeof response.data?.signature !== 'string') {
      throw new Error('Missing signer signature');
    }

    return Buffer.from(
      response.data.signature,
      'base64'
    ).toString('base64url');
  } catch (error) {
    console.error(
      'Signing failed:',
      error.response?.data ?? error.message
    );

    throw error;
  }
}

// ------------------------------------------------------------
// Presentation Frame
// ------------------------------------------------------------

function normalizePresentationFrame(frame) {
  if (frame === undefined || frame === null) {
    return {};
  }

  if (Array.isArray(frame)) {
    const result = Object.create(null);

    for (const claim of frame) {
      if (
        typeof claim !== 'string' ||
        !claim.trim() ||
        ['__proto__', 'constructor', 'prototype'].includes(claim)
      ) {
        throw new Error('Invalid disclosure claim');
      }

      result[claim] = true;
    }

    return result;
  }

  if (typeof frame !== 'object') {
    throw new Error(
      'presentationFrame must be an object or string array'
    );
  }

  return frame;
}

// ------------------------------------------------------------
// Issue
// ------------------------------------------------------------

app.post('/issue', async (req, res) => {
  try {
    const {
      issuer,
      subject,
      vct,
      holder,
      disclosureFrame
    } = req.body;

    if (typeof vct !== 'string' || !vct) {
      throw new Error('Missing vct');
    }

    if (
      !issuer?.signer?.alg ||
      !issuer.signer.kid ||
      !issuer.signer.namespace ||
      !issuer.signer.key
    ) {
      throw new Error('Issuer signer metadata missing');
    }

    if (!holder || !subject?.claims || !subject.iss) {
      throw new Error('Holder or subject missing');
    }

    const header = {
      alg: issuer.signer.alg,
      typ: 'dc+sd-jwt',
      kid: issuer.signer.kid
    };

    const claims = {
      ...subject.claims,
      ...(holder.cnf ? { cnf: holder.cnf } : {}),
      iss: subject.iss,
      iat: subject.iat ?? Math.floor(Date.now() / 1000),
      vct,
      exp: subject.exp
    };

    const instance = new SDJwtVcInstance({
      signer: data => signerFunc(issuer.signer, data),
      signAlg: issuer.signer.alg,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt
    });

    const sdjwt = await instance.issue(
      claims,
      disclosureFrame,
      { header }
    );

    res.json({ sdjwt });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ------------------------------------------------------------
// Verify
// ------------------------------------------------------------

app.post('/verify', async (req, res) => {
  const {
    sdjwt,
    disclosureFrame,
    verifyKeyBinding = false,
    nonce,
    aud
  } = req.body;

  try {
    if (typeof sdjwt !== 'string' || !sdjwt) {
      throw new Error('sdjwt required');
    }

    if (verifyKeyBinding && (!nonce || !aud)) {
      throw new Error('nonce and aud required');
    }

    logVerification('start', {
      verifyKeyBinding: !!verifyKeyBinding,
      ...describePresentation(sdjwt)
    });

    const issuerJwt = sdjwt.split('~')[0];
    const issuerParts = issuerJwt.split('.');

    if (issuerParts.length !== 3) {
      throw new Error('Invalid issuer JWT');
    }

    const issuerPayload = JSON.parse(
      Buffer.from(issuerParts[1], 'base64url').toString('utf8')
    );

    // Verify the holder's KB-JWT signature using the
    // confirmation key from the issuer-signed credential.
    const kbVerifier = async (data, sig) => {
      const [encodedHeader] = data.split('.');

      const header = JSON.parse(
        Buffer.from(encodedHeader, 'base64url').toString('utf8')
      );

      if (header.alg !== 'ES256') {
        throw new Error('Unsupported key binding algorithm');
      }

      const jwk = await resolveHolderJwk(issuerPayload.cnf);

      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
        throw new Error(
          'Key binding key must be EC P-256'
        );
      }

      const valid = crypto.verify(
        'sha256',
        Buffer.from(data),
        {
          key: jwk,
          format: 'jwk',
          dsaEncoding: 'ieee-p1363'
        },
        Buffer.from(sig, 'base64url')
      );

      logVerification('kb_signature', {
        valid,
        keySource: issuerPayload.cnf?.jwk
          ? 'jwk'
          : 'kid'
      });

      return valid;
    };

    const instance = new SDJwtVcInstance({
      ...createVerifier(),
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      kbVerifier,
      statusListFetcher: async uri => (
        await axios.get(uri, {
          headers: {
            Accept: 'application/statuslist+jwt'
          }
        })
      ).data
    });

    const decoded = await decodeSdJwt(sdjwt, digest);

    const claims = await getClaims(
      decoded.jwt.payload,
      decoded.disclosures,
      digest
    );

    const requiredKeys = Array.isArray(disclosureFrame)
      ? [...disclosureFrame, 'vct']
      : ['vct'];

    // The library must validate issuer signature,
    // disclosures, KB signature and SD hash.
    const token = await instance.verify(
      sdjwt,
      requiredKeys,
      verifyKeyBinding
    );

    logVerification('library_result', {
      resultKeys: Object.keys(token ?? {}),
      decodedKeys: Object.keys(decoded ?? {}),
      resultHasKb: !!token?.kb,
      decodedHasKb: !!decoded?.kb
    });

    if (verifyKeyBinding) {
      // Different library versions can expose the KB-JWT
      // in different result objects.
      // This fallback is safe only if instance.verify()
      // has already performed KB signature/hash validation.
      const kb = token?.kb ?? decoded?.kb ?? decoded.kbJwt;

      if (!kb) {
        throw new Error('Key binding missing');
      }

      if (kb.payload?.nonce !== nonce) {
        throw new Error('Nonce not valid');
      }

      if (kb.payload?.aud !== aud) {
        throw new Error('Audience not valid');
      }
    }

    logVerification('success', {
      verifyKeyBinding: !!verifyKeyBinding
    });

    res.json({
      claims,
      result: {
        isValid: true,
        isValidJwtPayload: !!token.payload,
        isSignatureValid: true,
        isStatusValid: true,
        areRequiredClaimsIncluded: true,
        isKeyBindingValid:
          !verifyKeyBinding || !!(token?.kb ?? decoded?.kb?? decoded?.kbJwt),
        containsExpectedKeyBinding:
          !verifyKeyBinding || !!(token?.kb ?? decoded?.kb?? decoded?.kbJwt)
      }
    });
  } catch (error) {
    console.error(JSON.stringify({
      event: 'sdjwt.verify',
      stage: 'failure',
      error: error.message,
      name: error.name
    }));

    res.status(400).json({
      error: error.message
    });
  }
});

// ------------------------------------------------------------
// Present
// ------------------------------------------------------------

app.post('/present', async (req, res) => {
  try {
    const {
      sdjwt,
      holder,
      nonce,
      aud
    } = req.body;

    if (typeof sdjwt !== 'string' || !sdjwt) {
      throw new Error('sdjwt required');
    }

    if (
      !holder?.signer?.alg ||
      !holder.signer.namespace ||
      !holder.signer.key
    ) {
      throw new Error('holder.signer missing');
    }

    if (!nonce || !aud) {
      throw new Error('nonce and aud required');
    }

    const frame = normalizePresentationFrame(
      req.body.presentationFrame ??
      req.body.disclosureFrame
    );

    const instance = new SDJwtVcInstance({
      kbSigner: data => signerFunc(holder.signer, data),
      kbSignAlg: holder.signer.alg,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt
    });

    const presented = await instance.present(
      sdjwt,
      frame,
      {
        kb: {
          payload: {
            iat: Math.floor(Date.now() / 1000),
            nonce,
            aud
          }
        }
      }
    );

    const disclosureCount = Math.max(
      0,
      presented.split('~').length - 2
    );

    console.info('SD-JWT presentation', {
      requestedClaims: Object.keys(frame),
      disclosureCount
    });

    if (
      Object.keys(frame).length &&
      disclosureCount === 0
    ) {
      throw new Error(
        'No disclosures included despite non-empty presentationFrame'
      );
    }

    res.json({
      sdjwt: presented
    });
  } catch (error) {
    console.error(
      'Presentation failed:',
      error.message
    );

    res.status(400).json({
      error: error.message
    });
  }
});

// ------------------------------------------------------------
// Health
// ------------------------------------------------------------

app.get('/isAlive', (_req, res) => {
  res.sendStatus(200);
});

app.listen(
  Number(process.env.PORT || 8080),
  () => console.info('SD-JWT service listening')
);
