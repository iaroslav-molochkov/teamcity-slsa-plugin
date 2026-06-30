package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.Map;

/** SLSA {@code externalParameters}: requester-supplied inputs. Absent fields are omitted on serialization. */
public record ExternalParameters(
        String buildTypeId,
        String projectId,
        String branch,
        Boolean personal,
        Map<String, String> customBuildParameters) {
}
