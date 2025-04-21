# SD JWT Service

This service just creates SD-JWT encodings with disclosures and verifies it. Keypair is just a dummy one for signature, dont use it as standard and resign the token always.

# Startup

Make sure the resolver is present: 

```
docker pull transmute/restricted-resolver:latest
```

Connect the TSA service via docker or via port forward.

Make sure the hashicorp vault is running and keys are initialized.

Start service.

```
node server.js --env-file=.env
``` 

Ensure to set SIGNER_SIGN_URL and RESOLVER_URL to the tsa signer service and the resolver url.

# Open API

The api can be called via http://localhost:3000/api-docs/#/

# SD JWT Eval

You can check here the output of the token: https://www.sdjwt.co/decode