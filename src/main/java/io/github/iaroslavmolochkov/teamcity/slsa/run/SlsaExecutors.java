package io.github.iaroslavmolochkov.teamcity.slsa.run;


import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/** Small helper for the plugin's named daemon thread pools. */
final class SlsaExecutors {

    private SlsaExecutors() {
    }

    /** Default pool size: the CPU count, with a floor of 2. */
    static int defaultPoolSize() {
        return Math.max(2, Runtime.getRuntime().availableProcessors());
    }

    static ExecutorService fixedDaemonPool(int threads, String namePrefix) {
        return Executors.newFixedThreadPool(threads, daemonThreadFactory(namePrefix));
    }

    private static ThreadFactory daemonThreadFactory(String namePrefix) {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, namePrefix + "-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
