package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

/** SLSA {@code externalParameters}: requester-controlled inputs. Absent fields are omitted on serialization. */
public record ExternalParameters(
        String buildTypeId,
        String buildTypeName,
        String projectId,
        Trigger trigger,
        String branch,
        Boolean branchIsDefault,
        Boolean personal) {
}
