package io.github.iaroslavmolochkov.slsa.persist;

public class ProvenancePublishingException extends RuntimeException {

    public ProvenancePublishingException(String message, Exception ex) {
        super(message, ex);
    }
    
}
