package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.Map;

/** A resolved input (in-toto ResourceDescriptor): URI, digest, and optional annotations. */
public record ResolvedDependency(String uri,
                                 Map<String, String> digest,
                                 String name,
                                 Map<String, String> annotations) {
}
