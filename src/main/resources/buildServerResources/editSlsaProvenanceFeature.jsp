<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="forms" tagdir="/WEB-INF/tags/forms" %>
<%@ taglib prefix="bs" tagdir="/WEB-INF/tags" %>

<tr>
  <td colspan="2">
    <em>Generates and signs SLSA v1.0 provenance for this configuration's artifacts, server-side,
      published as the <code>slsa/provenance.intoto.jsonl</code> artifact.</em>
  </td>
</tr>

<tr>
  <th><label for="slsa.signer">Signer:</label></th>
  <td>
    <props:selectProperty name="slsa.signer" id="slsaSigner" className="mediumField" onchange="BS.Slsa.updateSignerFields()">
      <props:option value="server">Server key (your PEM private key)</props:option>
      <props:option value="aws-kms-default">AWS KMS &mdash; default provider chain</props:option>
      <props:option value="aws-kms-static">AWS KMS &mdash; access key</props:option>
      <props:option value="aws-kms-assume-role">AWS KMS &mdash; assume an IAM role</props:option>
    </props:selectProperty>
    <span class="smallNote">Where the signing key lives. AWS KMS (key never leaves AWS) is recommended;
      the server key reads a PEM from the server's disk.</span>
  </td>
</tr>

<tr class="slsa-server">
  <th><label for="slsa.server.privateKeyPath">Private key file: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.server.privateKeyPath" className="longField"/>
    <span class="smallNote">Absolute path to an EC or RSA PEM key on the server (PKCS#8, PKCS#1 or SEC1),
      readable only by the server process (e.g. <code>chmod 600</code>). Keep the matching public key for
      verifiers; the DSSE <code>keyid</code> is <code>sha256:&lt;public key&gt;</code>.</span>
  </td>
</tr>

<tr class="slsa-kms">
  <th><label for="slsa.aws.region">AWS region: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.aws.region" className="longField"/>
    <span class="smallNote">The KMS key's region, e.g. <code>us-east-1</code>. Optional for the default provider chain; required otherwise.</span>
  </td>
</tr>

<tr class="slsa-kms">
  <th><label for="slsa.kms.keyId">KMS key id / ARN: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.kms.keyId" className="longField"/>
    <span class="smallNote">Asymmetric SIGN_VERIFY key: id, alias, or ARN.</span>
  </td>
</tr>

<tr class="slsa-kms">
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

<tr class="slsa-static">
  <th><label for="slsa.aws.accessKeyId">Access key id: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.aws.accessKeyId" className="longField"/>
  </td>
</tr>

<tr class="slsa-static">
  <th><label for="secure:slsa.aws.secretAccessKey">Secret access key: <l:star/></label></th>
  <td>
    <props:passwordProperty name="secure:slsa.aws.secretAccessKey" className="longField"/>
    <span class="smallNote">Stored encrypted.</span>
  </td>
</tr>

<tr class="slsa-assume">
  <th><label for="slsa.aws.assumeRole.arn">Role ARN: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.aws.assumeRole.arn" className="longField"/>
    <span class="smallNote">Assumed (scoped to <code>kms:Sign</code>) before signing.</span>
  </td>
</tr>

<tr class="slsa-assume">
  <th><label for="slsa.aws.assumeRole.sessionName">Session name:</label></th>
  <td><props:textProperty name="slsa.aws.assumeRole.sessionName" className="longField"/></td>
</tr>

<tr class="slsa-assume">
  <th><label for="slsa.aws.assumeRole.externalId">External id:</label></th>
  <td><props:textProperty name="slsa.aws.assumeRole.externalId" className="longField"/></td>
</tr>

<tr class="slsa-assume">
  <th><label for="slsa.aws.assumeRole.durationSeconds">Session duration (s):</label></th>
  <td><props:textProperty name="slsa.aws.assumeRole.durationSeconds" className="mediumField"/></td>
</tr>

<tr class="slsa-assume">
  <th><label for="slsa.aws.stsEndpoint">STS endpoint:</label></th>
  <td>
    <props:textProperty name="slsa.aws.stsEndpoint" className="longField"/>
    <span class="smallNote">Optional STS endpoint override (regional or VPC).</span>
  </td>
</tr>

<script type="text/javascript">
  BS.Slsa = {
    updateSignerFields: function () {
      var signer = $('slsaSigner').value;
      $j(".slsa-server, .slsa-kms, .slsa-static, .slsa-assume").hide();
      if (signer === "server") {
        $j(".slsa-server").show();
      } else {
        $j(".slsa-kms").show();
        if (signer === "aws-kms-static") {
          $j(".slsa-static").show();
        }
        if (signer === "aws-kms-assume-role") {
          $j(".slsa-assume").show();
        }
      }
    }
  };
  BS.Slsa.updateSignerFields();
</script>
