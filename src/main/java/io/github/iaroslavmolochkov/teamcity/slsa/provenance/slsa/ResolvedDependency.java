package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.Map;

/**
 * A resolved input (e.g. a VCS revision) identified by URI and digest, with optional annotations
 * (branch, commit author/message/date). Mirrors an in-toto ResourceDescriptor.
 */
public record ResolvedDependency(String uri, Map<String, String> digest, String name,
                                 Map<String, String> annotations) {
}
