# Certificate Request

You can use certificate-request to generate a private key and a PKCS #10 certificate signing request in PEM format.

## Install

To install library dependencies, run:

```shell
npm ci
```

To build a standalone library version, run:

```shell
npm run build
```

## Usage

```js
const companyData = {
  [PEM.OID.COMMON_NAME]: "*.example.org",
  [PEM.OID.ORGANIZATION_NAME]: "Example Corp.",
  [PEM.OID.EMAIL_ADDRESS]: "example@example.org"
};
const result = PEM.generate(companyData);
```
This function returns a Promise that fulfills in an object with properties certificateRequestPEM and privateKeyPEM. The values of these properties are strings in PEM format.
More complete example with usage of all possible fields of companyData is in example.js
