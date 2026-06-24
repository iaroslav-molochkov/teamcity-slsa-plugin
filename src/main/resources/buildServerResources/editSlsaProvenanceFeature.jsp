<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="forms" tagdir="/WEB-INF/tags/forms" %>
<%@ taglib prefix="bs" tagdir="/WEB-INF/tags" %>

<tr>
  <td colspan="2">
    <em>Generates a SLSA v1.0 provenance attestation for this configuration's build artifacts and
      signs it on the server. The signed DSSE envelope is published as the
      <code>slsa/provenance.intoto.jsonl</code> artifact.</em>
  </td>
</tr>

<tr>
  <th><label for="slsa.signer">Signer:</label></th>
  <td>
    <props:selectProperty name="slsa.signer" className="mediumField">
      <props:option value="server">Server key (your PEM private key)</props:option>
      <props:option value="aws-kms-default">AWS KMS &mdash; default provider chain</props:option>
      <props:option value="aws-kms-static">AWS KMS &mdash; access key</props:option>
      <props:option value="aws-kms-assume-role">AWS KMS &mdash; assume an IAM role</props:option>
    </props:selectProperty>
    <span class="smallNote">"Server key" signs with a private key you supply below &mdash; you keep the matching
      public key and give it to verifiers. The AWS KMS signers (key never leaves AWS) are recommended for
      real assurance; their settings further below apply only to them. The default provider chain reads
      env vars, profile, container or instance role on the server; "access key" uses the fields below;
      "assume role" assumes the role below over the default chain.</span>
  </td>
</tr>

<l:settingsGroup title="Server key (for the &quot;Server key&quot; signer)">
  <tr>
    <th><label for="secure:slsa.server.privateKey">Private key (PEM): <l:star/></label></th>
    <td>
      <props:passwordProperty name="secure:slsa.server.privateKey" className="longField"/>
      <span class="smallNote">An EC or RSA private key in PEM &mdash; PKCS#8 (<code>-----BEGIN PRIVATE KEY-----</code>),
        PKCS#1 (<code>-----BEGIN RSA PRIVATE KEY-----</code>) or SEC1 (<code>-----BEGIN EC PRIVATE KEY-----</code>).
        Encrypted keys are not supported. Stored encrypted. The DSSE <code>keyid</code> is derived from the
        key as <code>sha256:&lt;public key&gt;</code>; you keep the matching public key and give it to verifiers.</span>
    </td>
  </tr>
</l:settingsGroup>

<tr>
  <th><label for="slsa.aws.region">AWS region: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.aws.region" className="longField"/>
    <span class="smallNote">e.g. <code>us-east-1</code>. The KMS key's region. Optional for the default
      provider chain (resolved from the environment, e.g. <code>AWS_REGION</code>); required otherwise.</span>
  </td>
</tr>

<tr>
  <th><label for="slsa.kms.keyId">KMS key id / ARN: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.kms.keyId" className="longField"/>
    <span class="smallNote">An asymmetric SIGN_VERIFY key &mdash; key id, alias (<code>alias/&hellip;</code>) or full ARN.</span>
  </td>
</tr>

<tr>
  <th><label for="slsa.kms.signingAlgorithm">Signing algorithm: <l:star/></label></th>
  <td>
    <props:selectProperty name="slsa.kms.signingAlgorithm" className="mediumField">
      <c:forEach var="algorithm" items="${signingAlgorithms}">
        <props:option value="${algorithm}"><c:out value="${algorithm}"/></props:option>
      </c:forEach>
    </props:selectProperty>
    <span class="smallNote">Must match the KMS key spec (e.g. <code>ECDSA_SHA_256</code> for an ECC_NIST_P256 key).</span>
  </td>
</tr>

<tr>
  <th><label for="slsa.aws.accessKeyId">Access key id:</label></th>
  <td>
    <props:textProperty name="slsa.aws.accessKeyId" className="longField"/>
    <span class="smallNote">Required only for the "AWS KMS &mdash; access key" signer.</span>
  </td>
</tr>

<tr>
  <th><label for="secure:slsa.aws.secretAccessKey">Secret access key:</label></th>
  <td>
    <props:passwordProperty name="secure:slsa.aws.secretAccessKey" className="longField"/>
    <span class="smallNote">Stored encrypted. Required only for the "AWS KMS &mdash; access key" signer.</span>
  </td>
</tr>

<l:settingsGroup title="Assume role (for the &quot;AWS KMS &mdash; assume an IAM role&quot; signer)">
  <tr>
    <th><label for="slsa.aws.assumeRole.arn">Role ARN:</label></th>
    <td>
      <props:textProperty name="slsa.aws.assumeRole.arn" className="longField"/>
      <span class="smallNote">If set, the server assumes this role (scoped to <code>kms:Sign</code>) before signing.</span>
    </td>
  </tr>
  <tr>
    <th><label for="slsa.aws.assumeRole.sessionName">Session name:</label></th>
    <td><props:textProperty name="slsa.aws.assumeRole.sessionName" className="longField"/></td>
  </tr>
  <tr>
    <th><label for="slsa.aws.assumeRole.externalId">External id:</label></th>
    <td><props:textProperty name="slsa.aws.assumeRole.externalId" className="longField"/></td>
  </tr>
  <tr>
    <th><label for="slsa.aws.assumeRole.durationSeconds">Session duration (s):</label></th>
    <td><props:textProperty name="slsa.aws.assumeRole.durationSeconds" className="mediumField"/></td>
  </tr>
  <tr>
    <th><label for="slsa.aws.stsEndpoint">STS endpoint:</label></th>
    <td>
      <props:textProperty name="slsa.aws.stsEndpoint" className="longField"/>
      <span class="smallNote">Optional STS endpoint override, e.g. a regional or VPC endpoint.</span>
    </td>
  </tr>
</l:settingsGroup>
