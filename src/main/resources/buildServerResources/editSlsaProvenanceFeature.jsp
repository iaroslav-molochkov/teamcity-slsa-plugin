<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="forms" tagdir="/WEB-INF/tags/forms" %>
<%@ taglib prefix="bs" tagdir="/WEB-INF/tags" %>

<tr>
  <td colspan="2">
    <em>Generates and signs SLSA v1.0 provenance for the build's artifacts, server-side, and
      publishes the <code>provenance.sigstore.json</code> artifact.</em>
  </td>
</tr>

<tr>
  <th><label for="slsa.signer">Signer:</label></th>
  <td>
    <props:selectProperty name="slsa.signer" id="slsaSigner" className="mediumField" onchange="BS.Slsa.updateSignerFields()">
      <props:option value="server">Server key (PEM private key on the server)</props:option>
      <props:option value="aws-kms">AWS KMS</props:option>
    </props:selectProperty>
    <span class="error" id="error_slsa.signer"></span>
    <span class="smallNote">Where the signing key lives.</span>
  </td>
</tr>

<tr>
  <th><label for="slsa.failBuildOnError">Fail build on error:</label></th>
  <td>
    <props:checkboxProperty name="slsa.failBuildOnError"/>
    <span class="smallNote">When off (default), a provenance failure logs a warning; when on, it fails the build.</span>
  </td>
</tr>

<tr class="slsa-server">
  <th><label for="slsa.server.privateKeyPath">Private key file: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.server.privateKeyPath" className="longField"/>
    <span class="error" id="error_slsa.server.privateKeyPath"></span>
    <span class="smallNote">Absolute path to a PEM private key on the server (EC or RSA; PKCS#8, PKCS#1,
      or SEC1), readable only by the server process.</span>
  </td>
</tr>

<tr class="slsa-kms">
  <th><label for="slsa.aws.region">AWS region:</label></th>
  <td>
    <props:textProperty name="slsa.aws.region" className="longField"/>
    <span class="error" id="error_slsa.aws.region"></span>
    <span class="smallNote">KMS key region (e.g. <code>us-east-1</code>). Optional: when blank, the AWS SDK resolves
      the region from the environment (<code>AWS_REGION</code>, profile, or instance metadata).</span>
  </td>
</tr>

<tr class="slsa-kms">
  <th><label for="slsa.kms.keyId">KMS key id / ARN: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.kms.keyId" className="longField"/>
    <span class="error" id="error_slsa.kms.keyId"></span>
    <span class="smallNote">Asymmetric SIGN_VERIFY key: id, alias, or ARN.</span>
  </td>
</tr>

<tr class="slsa-kms">
  <th><label for="slsa.kms.signingAlgorithm">Signing algorithm: <l:star/></label></th>
  <td>
    <props:selectProperty name="slsa.kms.signingAlgorithm" className="mediumField">
      <props:option value="">-- Select algorithm --</props:option>
      <c:forEach var="algorithm" items="${signingAlgorithms}">
        <props:option value="${algorithm}"><c:out value="${algorithm}"/></props:option>
      </c:forEach>
    </props:selectProperty>
    <span class="error" id="error_slsa.kms.signingAlgorithm"></span>
    <span class="smallNote">Must match the key spec (e.g. <code>ECDSA_SHA_256</code> for an ECC_NIST_P256 key).</span>
  </td>
</tr>

<tr class="slsa-kms">
  <th><label for="slsa.aws.credentials">Credentials: <l:star/></label></th>
  <td>
    <props:selectProperty name="slsa.aws.credentials" id="slsaCredentials" className="mediumField"
                          onchange="BS.Slsa.updateSignerFields()">
      <props:option value="">-- Select credentials --</props:option>
      <props:option value="default-credentials">Default provider chain</props:option>
      <props:option value="static-credentials">Static access key</props:option>
    </props:selectProperty>
    <span class="error" id="error_slsa.aws.credentials"></span>
    <span class="smallNote">How the server authenticates to AWS: the default provider chain (env, profile,
      container/instance role) or an explicit access key.</span>
  </td>
</tr>

<tr class="slsa-static">
  <th><label for="slsa.aws.accessKeyId">Access key id: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.aws.accessKeyId" className="longField"/>
    <span class="error" id="error_slsa.aws.accessKeyId"></span>
  </td>
</tr>

<tr class="slsa-static">
  <th><label for="secure:slsa.aws.secretAccessKey">Secret access key: <l:star/></label></th>
  <td>
    <props:passwordProperty name="secure:slsa.aws.secretAccessKey" className="longField"/>
    <span class="error" id="error_secure:slsa.aws.secretAccessKey"></span>
    <span class="smallNote">Stored encrypted.</span>
  </td>
</tr>

<tr class="slsa-role">
  <th><label for="slsaAssumeRole">Assume an IAM role:</label></th>
  <td>
    <props:checkboxProperty name="slsa.aws.assumeRole.enabled" id="slsaAssumeRole"
                            onclick="BS.Slsa.updateSignerFields()"/>
    <span class="smallNote">Assume the specified IAM role with the selected credentials and sign with the resulting temporary credentials.</span>
  </td>
</tr>

<tr class="slsa-assume">
  <th><label for="slsa.aws.assumeRole.arn">Role ARN: <l:star/></label></th>
  <td>
    <props:textProperty name="slsa.aws.assumeRole.arn" className="longField"/>
    <span class="error" id="error_slsa.aws.assumeRole.arn"></span>
    <span class="smallNote">Assumed before signing. Scope it to <code>kms:Sign</code>.</span>
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
  <td>
    <props:textProperty name="slsa.aws.assumeRole.durationSeconds" className="mediumField"/>
    <span class="error" id="error_slsa.aws.assumeRole.durationSeconds"></span>
  </td>
</tr>

<tr class="slsa-assume">
  <th><label for="slsa.aws.stsEndpoint">STS endpoint:</label></th>
  <td>
    <props:textProperty name="slsa.aws.stsEndpoint" className="longField"/>
    <span class="smallNote">STS endpoint override (regional or VPC).</span>
  </td>
</tr>

<script type="text/javascript">
  BS.Slsa = {
    updateSignerFields: function () {
      var signer = $('slsaSigner').value;
      $j(".slsa-server, .slsa-kms, .slsa-static, .slsa-role, .slsa-assume").hide();

      if (signer === "server") {
        $j(".slsa-server").show();
      } else {
        $j(".slsa-kms").show();

        if ($('slsaCredentials').value === "static-credentials") {
          $j(".slsa-static").show();
        }

        $j(".slsa-role").show();

        if ($('slsaAssumeRole').checked) {
          $j(".slsa-assume").show();
        }
      }
    }
  };
  BS.Slsa.updateSignerFields();
</script>
