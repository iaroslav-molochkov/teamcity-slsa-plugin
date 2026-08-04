package io.github.iaroslavmolochkov.slsa.provenance.intoto;


import java.util.Map;

/** An in-toto Statement subject: a name and content digests keyed by algorithm. */
public record Subject(String name, Map<String, String> digest) {
}
