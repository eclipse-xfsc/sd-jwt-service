const express = require('express');
const { digest, generateSalt } = require('@sd-jwt/crypto-nodejs');
const { decodeSdJwt, getClaims } = require( '@sd-jwt/decode');
const crypto = require('crypto');
const axios = require('axios');
const { SDJwtVcInstance } = require('@sd-jwt/sd-jwt-vc'); // aktualisieren mit dem richtigen Pfad
const base64url = require('base64url');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');


const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'SD-JWT Service',
      version: '1.0.0',
      description: 'This is a service to generate and verify SD-JWT',
    },
  },
  apis: ['./server.js'], // Pfad zur API-Dokumentation
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
const app = express();
const port = process.env.PORT;

app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * components:
 *   schemas:
 *     SignerDetails:
 *        type: object
 *        properties:         
 *          kid:
 *            type: string
 *            example: did:web:xxxxx
 *            required: true
 *          alg:
 *            type: string
 *            example: ES256
 *            required: true
 *          namespace:
 *            type: string
 *            description: namespace of signer
 *            example: space
 *            required: true
 *          key: 
 *            type: string
 *            description: key of signer
 *            example: space
 *            required: true
 *          group: 
 *            type: string
 *            description: key of signer
 *            example: space
 *            required: true
 *     HolderDetails:
 *        type: object
 *        properties:
 *          cnf:
 *            type: object
 *            description: Public JWK of the Holder
 *            required: false
 *          signer:
 *            allOf:
 *              - $ref: '#/components/schemas/SignerDetails'
 *     PresentationBody:
 *        type: object
 *        properties:
 *          sdjwt:
 *            type: string
 *            example: eyJ0....
 *            required: true
 *          presentationFrame: 
 *            type: object
 *            example: {"email":true}
 *            required: true  
 *          holder:
 *             required: true
 *             allOf:
 *              - $ref: '#/components/schemas/HolderDetails' 
 *          nonce:
 *            required: true
 *            type: string 
 *          aud:
 *            required: true
 *            type: string 
 *     SubjectDetails:
 *        type: object
 *        properties:
 *          claims:
 *            type: object
 *            description: Json with claims
 *            required: false
 *          iss:
 *            type: string
 *            required: true
 *          iat: 
 *            type: string
 *            required: true
 *          exp: 
 *            type: string
 *            required: true
 *     IssuerDetails:
 *        type: object
 *        properties:    
 *          signer:
 *            allOf:
 *              - $ref: '#/components/schemas/SignerDetails' 
 *     DisclosureDetails:
 *        type: object
 *        properties:
 *          _sd:
 *            type: array
 *            example: ["email"]
 *            items:
 *               type: string
 *            required: false  
 *     IssueBody:
 *        type: object
 *        properties:
 *          vct:
 *            type: string
 *            example: eyJ0....
 *            required: true
 *          disclosureFrame:
 *            allOf:
 *              - $ref: '#/components/schemas/DisclosureDetails'  
 *          holder:
 *            allOf:
 *              - $ref: '#/components/schemas/HolderDetails'    
 *          subject:
 *            allOf:
 *              - $ref: '#/components/schemas/SubjectDetails'  
 *          issuer:
 *            allOf:
 *              - $ref: '#/components/schemas/IssuerDetails' 
 *     IssueResponse:
 *        type: object
 *        properties:
 *          sdjwt:
  *           type: string
  *           example: eyx....
  *           required: true
 *     VerifyBody:
 *        type: object 
 *        properties:  
 *          sdjwt:
 *            type: string
 *            example: eyJ0....
 *            required: true
 *          verifyKeyBinding:
 *            type: boolean
 *            example: false
 *            required: false
 *          disclosureFrame:
 *            type: array
 *            example: ["email","name"] 
 *            required: false
 *          aud: 
 *            type: string
 *            example: did:web:example
 *            required: false
 *          nonce: 
 *            type: string
 *            example: 223323
 *            required: false
 *     Error:
 *       type: object
 *       properties: 
 *          error: 
 *            type: string
 *            example: Invalid JWT
 *     VerifyResult:
 *       type: object
 *       properties:  
 *         isValid:
 *           type: boolean
 *           example: false
 *         isValidJwtPayload:
 *           type: boolean
 *           example: false
 *         isSignatureValid:
 *           type: boolean
 *           example: false
 *         isStatusValid:
 *           type: boolean
 *           example: false
 *         areRequiredClaimsIncluded:
 *           type: boolean
 *           example: false
 *         isKeyBindingValid:
 *           type: boolean
 *           example: false
 *         containsExpectedKeyBinding:
 *           type: boolean
 *           example: false
 *     VerifyResponse:
 *        type: object
 *        properties:
 *          claims: 
 *            type: object
 *          result:
 *           allOf:
 *              - $ref: '#/components/schemas/VerifyResult' 
 */


async function fetchDIDDocument(did) {
  try {
    const response = await axios.get(process.env.RESOLVER_URL+did);
    
     if (response.data && response.data.didDocument) {
      return response.data.didDocument;
    } else {
      return response.data
    }
  } catch (error) {
    console.error('Error during did doc retrieval', error);
    throw error;
  }
}

const createVerifier = () => {
  const verifier = async (data, sig) => {
    try {
      console.debug("Data:"+data+" Sig:" +  sig)

      const parts = data.split('.');
      const decodedParts = parts.map(part => Buffer.from(part,'base64url').toString('utf-8'));

      if (decodedParts != null) {
        const header = JSON.parse(decodedParts[0])
        const body = JSON.parse(decodedParts[1])
    
        var jwk = null

        if (!header) {
          throw new Error("header not parseable:" + decodedParts[0])
        }

        if (header.jwk) {
          jwk = header.jwk
        } else {
          if (header.kid) {
            const resolverResult =await fetchDIDDocument(header.kid)
  
            const parts = header.kid.split('#');

            var key = resolverResult.verificationMethod.find(obj => obj.id == header.kid)  

            if (!key) {
                key = resolverResult.verificationMethod.find(obj => obj.id == "#"+parts[1])  
            }


            jwk = key.publicKeyJwk
          }
        }

        if (jwk == null) {
         throw new Error("no public key for verification found")
        }

        console.log(jwk)
        
        return crypto.verify(null, Buffer.from(data), {
          key: jwk,
          format: 'jwk',
          dsaEncoding:'ieee-p1363'
        }, Buffer.from(sig, 'base64url'));

      } else {
        console.error('kid missing in token');
        throw error;
      }
    } catch (error) {
      console.log(error)
      return false
    }
  };
  return { verifier };
};

const signerFunc = async (keyMetadata,data) => {
      
  return await axios.post(process.env.SIGNER_SIGN_URL,{
     "namespace": keyMetadata.namespace,
     "group": keyMetadata.group,
     "key": keyMetadata.key,
     "data": Buffer.from(data).toString("base64")
   },
   {
   headers: {
       'Content-Type': 'application/json'
   }}).then(response => {

     const buffer = Buffer.from(response.data.signature, 'base64');
     console.debug("Data:"+data+" Sig:" + Buffer.from(buffer).toString('base64url'))
     return Buffer.from(buffer).toString('base64url')
   })
   .catch(error => {
       console.error('Error:', error.response ? error.response.data : error.message);
   });
 };


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
 *         content:
 *            application/json:
 *              schema: 
 *                 $ref: '#/components/schemas/Error'
 *       200:
 *         description: A JSON object containing a the issue response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/IssueResponse'
 */
app.post('/issue', async (req, res) => {
  const { issuer, subject,vct, holder,disclosureFrame } = req.body;
  try {
      if (!vct || typeof vct !== 'string') {
        throw new Error("Missing required parameter 'vct'")
      }

      if (!issuer|| !issuer.signer.alg || !issuer.signer.kid|| !issuer.signer.namespace || !issuer.signer.key ) {
        throw new Error("Issuer metadata are missing (Alg,Kid,namespace,key,group)")
      }

      if (!holder) {
        throw new Error("issuer metadata are missing ()")
      }

      if (issuer.kid) {

        const didDoc = await fetchDIDDocument(issuer.signer.kid)

        if (!didDoc) {
          throw new Error("The provided kid is not valid.")
        }
      }

      const header = {
        alg: issuer.signer.alg,
        typ: 'sd-jwt',
        kid: issuer.signer.kid,
      }

      const signer = async(data) => {
        return await signerFunc(issuer.signer,data)
      }

      const sdjwt = new SDJwtVcInstance({
        signer,
        signAlg: issuer.signer.alg,
        hasher: digest,
        hashAlg: 'SHA-256',
        saltGenerator: generateSalt,
      });

      var claims = {
        ...subject.claims,
        iss: subject.iss,
        iat: Math.floor(Date.now() / 1000),
        vct:vct,
        exp: subject.exp
      }

      if (holder.cnf) {
          claims = {
            ...subject.claims,
            cnf: holder.cnf,
            iss: subject.iss,
            iat:subject.iat,
            vct:vct,
            exp: subject.exp
          }
      }

      const encodedSdjwt = await sdjwt.issue(
        claims,
        disclosureFrame,
        {header}
      );

    res.json({ sdjwt: encodedSdjwt });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
 *         content:
 *            application/json:
 *              schema: 
 *                 $ref: '#/components/schemas/Error'
 *       200:
 *         description: A JSON object containing a the verify response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/VerifyResponse'
 */
app.post('/verify', async (req, res) => {
  const { sdjwt,disclosureFrame,verifyKeyBinding, nonce, aud } = req.body;
  const { verifier } = createVerifier()

  var result = {
    isValid: false,
    isValidJwtPayload: false,
    isSignatureValid: false,
    isStatusValid: false,
    // isNotBeforeValid: false,
    //isExpiryTimeValid: false,
    areRequiredClaimsIncluded: false,
    isKeyBindingValid: false,
    containsExpectedKeyBinding: false,
    //containsRequiredVcProperties: false,
  }


  const kbVerifier = async (data,sig) => {
    const parts = sdjwt.split('.');
    const decodedParts = parts.map(part => Buffer.from(part,'base64url').toString('utf-8'));

    if (decodedParts != null) {
      const body = JSON.parse(decodedParts[1])
      if (body.cnf) {  
        var jwk = {}

        if (!body.cnf.jwk) {
          throw "No JWK in body cnf available"
        }

        if (typeof body.cnf.jwk !== 'object') {
          jwk = JSON.parse(body.cnf.jwk)
        } else {
          jwk = body.cnf.jwk
        }
        
        return crypto.verify(null, Buffer.from(data), {
          key: jwk,
          format: 'jwk',
          dsaEncoding:'ieee-p1363'
        }, Buffer.from(sig, 'base64url'));
      }
    }
  }


  const sdjwtInstance = new SDJwtVcInstance({
    verifier,
    hasher: digest,
    hashAlg: 'SHA-256',
    saltGenerator: generateSalt,
    kbVerifier: kbVerifier,
    statusListFetcher: async (uri) => {
      return await axios.get(uri)
    },
  });

  const requiredKeys = disclosureFrame ? [...disclosureFrame, 'vct'] : ['vct']


  try {
      const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
      console.debug('The decoded Disclosures are:');
      console.debug(JSON.stringify(decodedSdJwt.disclosures, null, 2));

      const claims = await getClaims(
        decodedSdJwt.jwt.payload,
        decodedSdJwt.disclosures,
        digest,
      );

      console.debug('The claims are:');
      console.debug(JSON.stringify(claims, null, 2));

      const token = await sdjwtInstance.verify(sdjwt,requiredKeys,verifyKeyBinding !== undefined?verifyKeyBinding:false);

      if (verifyKeyBinding == undefined) {
        result.isKeyBindingValid = true
        result.containsExpectedKeyBinding = true
      }
      result.isSignatureValid = true
      result.isValid = true
      result.isStatusValid = true
      result.areRequiredClaimsIncluded = true
 
      if (token.payload) {
        result.isValidJwtPayload = true
      }

      if (token.kb) {
        result.isKeyBindingValid = true

        if (token.kb.payload.nonce != nonce) {
          throw new Error("Nonce not valid")
        }

        if (token.kb.payload.aud != aud) {
          throw new Error("Audience not valid")
        }

        result.containsExpectedKeyBinding = true
      }

    res.json({"result":result,"claims":claims});
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * @swagger
 * /present:
 *   post:
 *     summary: Returns the token for presentation and with disclosure
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/PresentationBody'
 *     responses:
 *       400:
 *         content:
 *            application/json:
 *              schema: 
 *                 $ref: '#/components/schemas/Error'
 *       200:
 *         description: A JSON object containing a the issue response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/IssueResponse'
 */
app.post("/present",async(req,res) => {
  const { sdjwt,disclosureFrame,holder, nonce,aud} = req.body;

  try {
        const kbsigner  = async(data) => {
          return await signerFunc(holder.signer,data)
        }

        const sdjwtInstance = new SDJwtVcInstance({
          kbSigner: kbsigner,
          kbSignAlg: holder.signer.alg,
          hasher: digest,
          hashAlg: 'SHA-256',
          saltGenerator: generateSalt
        });
      
        var presentationFrame = disclosureFrame
        if (!presentationFrame){
          const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
          presentationFrame=[]
          decodedSdJwt.disclosures.forEach(function(value){
            presentationFrame[value.key] = false
          });

        }

        const compactDerivedSdJwtVc = await sdjwtInstance.present(sdjwt, presentationFrame,{
          kb:{payload: {
            iat: Math.floor(Date.now() / 1000),
            nonce:nonce,
            aud: aud
          }}
        })

        res.json({sdjwt:compactDerivedSdJwtVc});
}  catch (error) {
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
 *         description: a 200 of service availability
 */
app.get('/isAlive', async (req, res) =>{
  res.status(200).send()
})


app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});