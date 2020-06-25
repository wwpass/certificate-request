function addToPage(text){
  var outer = document.createElement('div');
  var inner = document.createElement('code');
  inner.style.cssText = 'white-space: pre-wrap;';
  inner.textContent = text;
  outer.appendChild(inner);
  document.body.appendChild(outer);
}

const companyData = {
  [PEM.OID.COMMON_NAME]: "*.example.org",
  [PEM.OID.ORGANIZATION_NAME]: "Example Corp.",
  [PEM.OID.EMAIL_ADDRESS]: "example@example.org"
  [PEM.OID.ORGANIZATIONAL_UNIT_NAME]: "Finance",
  [PEM.OID.LOCALITY_NAME]: "San Francisco",
  [PEM.OID.STATE_OR_PROVINCE_NAME]: "California",
  [PEM.OID.COUNTRY_NAME]: "US",
  [PEM.OID.EMAIL_ADDRESS]: "example@example.org",
  [PEM.OID.EXTENSION_REQUEST]: [
    {
      [PEM.EXTN.ID]: "2.5.29.36",
      [PEM.EXTN.CRITICAL]: false,
      [PEM.EXTN.VALUE]: new Uint8Array([48, 6, 2, 1, 1, 2, 1, 2]).buffer
    },
    {
      [PEM.EXTN.ID]: "2.5.29.19",
      [PEM.EXTN.CRITICAL]: false,
      [PEM.EXTN.VALUE]: new Uint8Array([48, 6, 1, 1, 0, 2, 1, 0]).buffer
    }
  ],
  [PEM.OID.CHALLENGE_PASSWORD]: "qwerty",
  [PEM.OID.UNSTRUCTURED_NAME]: "Some Name"
};
PEM.generate(companyData).then(result => {
  addToPage(result.CSR_PEM);
  addToPage(result.privateKeyPEM);
});
