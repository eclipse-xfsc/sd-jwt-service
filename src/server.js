// Reconstructed from the server.js pasted in the conversation.
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
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerJsdoc({
  definition: { openapi: '3.0.0', info: { title: 'SD-JWT Service', version: '1.0.0' } },
  apis: ['./server.js']
})));

async function fetchDIDDocument(did) {
  const response = await axios.get(`${process.env.DID_RESOLVER}/1.0/identifiers/${encodeURIComponent(did)}`);
  return response.data?.didDocument ?? response.data;
}

function createVerifier() {
  return { verifier: async (data, sig) => {
    try {
      const [encodedHeader, encodedPayload] = data.split('.');
      if (!encodedHeader || !encodedPayload) throw new Error('Invalid JWT signing input');
      const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
      let jwk = header.jwk;
      if (!jwk && header.kid) {
        const kid = header.kid;
        const did = kid.startsWith('did:') ? kid.split('#')[0] : kid.startsWith('#') ? payload.iss : null;
        if (!did || !did.startsWith('did:')) throw new Error('Unsupported kid');
        const document = await fetchDIDDocument(did);
        const fullKid = kid.startsWith('#') ? did + kid : kid;
        const fragment = fullKid.includes('#') ? fullKid.slice(fullKid.indexOf('#')) : null;
        const method = document.verificationMethod?.find(m => m.id === fullKid || (fragment && m.id === fragment));
        if (!method?.publicKeyJwk) throw new Error(`Verification method not found: ${fullKid}`);
        jwk = method.publicKeyJwk;
      }
      if (!jwk) throw new Error('Missing verification key');
      return crypto.verify(null, Buffer.from(data), {
        key: jwk, format: 'jwk', dsaEncoding: 'ieee-p1363'
      }, Buffer.from(sig, 'base64url'));
    } catch (error) {
      console.error('Issuer signature verification failed:', error);
      return false;
    }
  }};
}

async function signerFunc(keyMetadata, data) {
  try {
    const response = await axios.post(process.env.SIGNER_SIGN_URL, {
      namespace: keyMetadata.namespace, group: keyMetadata.group,
      key: keyMetadata.key, data: Buffer.from(data).toString('base64')
    }, { headers: { 'Content-Type': 'application/json' } });
    if (typeof response.data?.signature !== 'string') throw new Error('Missing signer signature');
    return Buffer.from(response.data.signature, 'base64').toString('base64url');
  } catch (error) {
    console.error('Signing failed:', error.response?.data ?? error.message);
    throw error;
  }
}

function normalizePresentationFrame(frame) {
  if (frame === undefined || frame === null) return {};
  if (Array.isArray(frame)) {
    const result = Object.create(null);
    for (const claim of frame) {
      if (typeof claim !== 'string' || !claim.trim() || ['__proto__', 'constructor', 'prototype'].includes(claim)) {
        throw new Error('Invalid disclosure claim');
      }
      result[claim] = true;
    }
    return result;
  }
  if (typeof frame !== 'object') throw new Error('presentationFrame must be an object or string array');
  return frame;
}

/**
 * @swagger
 * components:
 *   schemas:
 *     SignerDetails:
 *       type: object
 *       properties:
 *         kid:
 *           type: string
 *           example: did:web:xxxxx
 *         alg:
 *           type: string
 *           example: ES256
 *         namespace:
 *           type: string
 *           example: space
 *         key:
 *           type: string
 *           example: space
 *         group:
 *           type: string
 *           example: space
 *     HolderDetails:
 *       type: object
 *       properties:
 *         cnf:
 *           type: object
 *           description: Public JWK of the Holder
 *         signer:
 *           $ref: '#/components/schemas/SignerDetails'
 *     PresentationBody:
 *       type: object
 *       required: [sdjwt, holder, nonce, aud]
 *       properties:
 *         sdjwt:
 *           type: string
 *           example: eyJ0....
 *         presentationFrame:
 *           type: object
 *           description: Map of claim names to booleans, e.g. {test: true}
 *           additionalProperties:
 *             type: boolean
 *           example: {email: true}
 *         disclosureFrame:
 *           type: array
 *           description: Legacy alternative to presentationFrame
 *           items:
 *             type: string
 *           example: [email]
 *         holder:
 *           $ref: '#/components/schemas/HolderDetails'
 *         nonce:
 *           type: string
 *         aud:
 *           type: string
 *     SubjectDetails:
 *       type: object
 *       properties:
 *         claims:
 *           type: object
 *           description: JSON with claims
 *         iss:
 *           type: string
 *         iat:
 *           type: integer
 *         exp:
 *           type: integer
 *     IssuerDetails:
 *       type: object
 *       properties:
 *         signer:
 *           $ref: '#/components/schemas/SignerDetails'
 *     DisclosureDetails:
 *       type: object
 *       properties:
 *         _sd:
 *           type: array
 *           example: [email]
 *           items:
 *             type: string
 *     IssueBody:
 *       type: object
 *       properties:
 *         vct:
 *           type: string
 *           example: https://example.org/credential-type
 *         disclosureFrame:
 *           $ref: '#/components/schemas/DisclosureDetails'
 *         holder:
 *           $ref: '#/components/schemas/HolderDetails'
 *         subject:
 *           $ref: '#/components/schemas/SubjectDetails'
 *         issuer:
 *           $ref: '#/components/schemas/IssuerDetails'
 *     IssueResponse:
 *       type: object
 *       properties:
 *         sdjwt:
 *           type: string
 *           example: eyJ0....
 *     VerifyBody:
 *       type: object
 *       properties:
 *         sdjwt:
 *           type: string
 *         verifyKeyBinding:
 *           type: boolean
 *           example: false
 *         disclosureFrame:
 *           type: array
 *           items:
 *             type: string
 *           example: [email, name]
 *         aud:
 *           type: string
 *         nonce:
 *           type: string
 *     Error:
 *       type: object
 *       properties:
 *         error:
 *           type: string
 *           example: Invalid JWT
 *     VerifyResult:
 *       type: object
 *       properties:
 *         isValid:
 *           type: boolean
 *         isValidJwtPayload:
 *           type: boolean
 *         isSignatureValid:
 *           type: boolean
 *         isStatusValid:
 *           type: boolean
 *         areRequiredClaimsIncluded:
 *           type: boolean
 *         isKeyBindingValid:
 *           type: boolean
 *         containsExpectedKeyBinding:
 *           type: boolean
 *     VerifyResponse:
 *       type: object
 *       properties:
 *         claims:
 *           type: object
 *         result:
 *           $ref: '#/components/schemas/VerifyResult'
 */

/**
 * @swagger
 * /issue:
 *   post:
 *     summary: Returns the created token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/IssueBody'
 *     responses:
 *       400:
 *         description: Invalid request
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       200:
 *         description: Successful response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/IssueResponse'
 */
app.post('/issue', async (req, res) => {
  try {
    const { issuer, subject, vct, holder, disclosureFrame } = req.body;
    if (typeof vct !== 'string' || !vct) throw new Error('Missing vct');
    if (!issuer?.signer?.alg || !issuer.signer.kid || !issuer.signer.namespace || !issuer.signer.key) {
      throw new Error('Issuer signer metadata missing');
    }
    if (!holder || !subject?.claims || !subject.iss) throw new Error('Holder or subject missing');
    const header = { alg: issuer.signer.alg, typ: 'dc+sd-jwt', kid: issuer.signer.kid };
    const claims = {
      ...subject.claims, ...(holder.cnf ? { cnf: holder.cnf } : {}),
      iss: subject.iss, iat: subject.iat ?? Math.floor(Date.now() / 1000),
      vct, exp: subject.exp
    };
    const instance = new SDJwtVcInstance({
      signer: data => signerFunc(issuer.signer, data), signAlg: issuer.signer.alg,
      hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt
    });
    res.json({ sdjwt: await instance.issue(claims, disclosureFrame, { header }) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

/**
 * @swagger
 * /verify:
 *   post:
 *     summary: Returns the verify response
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/VerifyBody'
 *     responses:
 *       400:
 *         description: Invalid request
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       200:
 *         description: Successful response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/VerifyResponse'
 */
app.post('/verify', async (req, res) => {
  const { sdjwt, disclosureFrame, verifyKeyBinding = false, nonce, aud } = req.body;
  try {
    if (typeof sdjwt !== 'string' || !sdjwt) throw new Error('sdjwt required');
    if (verifyKeyBinding && (!nonce || !aud)) throw new Error('nonce and aud required');
    const issuerJwt = sdjwt.split('~')[0];
    const issuerParts = issuerJwt.split('.');
    if (issuerParts.length !== 3) throw new Error('Invalid issuer JWT');
    const issuerPayload = JSON.parse(Buffer.from(issuerParts[1], 'base64url').toString('utf8'));
    const kbVerifier = async (data, sig) => {
      const jwk = issuerPayload.cnf?.jwk;
      if (!jwk) throw new Error('No cnf.jwk in issuer JWT');
      return crypto.verify(null, Buffer.from(data), {
        key: typeof jwk === 'string' ? JSON.parse(jwk) : jwk,
        format: 'jwk', dsaEncoding: 'ieee-p1363'
      }, Buffer.from(sig, 'base64url'));
    };
    const instance = new SDJwtVcInstance({
      ...createVerifier(), hasher: digest, hashAlg: 'sha-256',
      saltGenerator: generateSalt, kbVerifier,
      statusListFetcher: async uri => (await axios.get(uri, {
        headers: { Accept: 'application/statuslist+jwt' }
      })).data
    });
    const decoded = await decodeSdJwt(sdjwt, digest);
    const claims = await getClaims(decoded.jwt.payload, decoded.disclosures, digest);
    const requiredKeys = Array.isArray(disclosureFrame) ? [...disclosureFrame, 'vct'] : ['vct'];
    const token = await instance.verify(sdjwt, requiredKeys, verifyKeyBinding);
    if (verifyKeyBinding) {
      if (!token.kb) throw new Error('Key binding missing');
      if (token.kb.payload.nonce !== nonce) throw new Error('Nonce not valid');
      if (token.kb.payload.aud !== aud) throw new Error('Audience not valid');
    }
    res.json({ claims, result: {
      isValid: true, isValidJwtPayload: !!token.payload, isSignatureValid: true,
      isStatusValid: true, areRequiredClaimsIncluded: true,
      isKeyBindingValid: !verifyKeyBinding || !!token.kb,
      containsExpectedKeyBinding: !verifyKeyBinding || !!token.kb
    }});
  } catch (error) { console.error('Verification failed:', error); res.status(400).json({ error: error.message }); }
});

/**
 * @swagger
 * /present:
 *   post:
 *     summary: Returns the token for presentation with disclosure
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/PresentationBody'
 *     responses:
 *       400:
 *         description: Invalid request
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       200:
 *         description: Successful response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/IssueResponse'
 */
app.post('/present', async (req, res) => {
  try {
    const { sdjwt, holder, nonce, aud } = req.body;
    if (typeof sdjwt !== 'string' || !sdjwt) throw new Error('sdjwt required');
    if (!holder?.signer?.alg || !holder.signer.namespace || !holder.signer.key) throw new Error('holder.signer missing');
    if (!nonce || !aud) throw new Error('nonce and aud required');
    // Go sends presentationFrame; disclosureFrame remains supported for old callers.
    const frame = normalizePresentationFrame(req.body.presentationFrame ?? req.body.disclosureFrame);
    const instance = new SDJwtVcInstance({
      kbSigner: data => signerFunc(holder.signer, data),
      kbSignAlg: holder.signer.alg, hasher: digest,
      hashAlg: 'sha-256', saltGenerator: generateSalt
    });
    const presented = await instance.present(sdjwt, frame, {
      kb: { payload: { iat: Math.floor(Date.now() / 1000), nonce, aud } }
    });
    const disclosureCount = Math.max(0, presented.split('~').length - 2);
    console.info('SD-JWT presentation', { requestedClaims: Object.keys(frame), disclosureCount });
    if (Object.keys(frame).length && disclosureCount === 0) {
      throw new Error('No disclosures included despite non-empty presentationFrame');
    }
    res.json({ sdjwt: presented });
  } catch (error) {
    console.error('Presentation failed:', error);
    res.status(400).json({ error: error.message });
  }
});

/**
 * @swagger
 * /isAlive:
 *   get:
 *     summary: Returns the is alive response
 *     responses:
 *       200:
 *         description: Service is alive
 */
app.get('/isAlive', (_req, res) => res.sendStatus(200));
app.listen(Number(process.env.PORT || 8080), () => console.info('SD-JWT service listening'));
