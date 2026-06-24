package io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto;


import java.util.Map;

/**
 * An in-toto Statement subject: a name and a set of content digests (algorithm -&gt; lowercase hex).
 *
 * @param name   the artifact path
 * @param digest e.g. {@code {"sha256": "abc..."}}
 */
public record Subject(String name, Map<String, String> digest) {

    public static Subject sha256(String name, String hexDigest) {
        return new Subject(name, Map.of("sha256", hexDigest));
    }
}
