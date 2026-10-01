import java.util.concurrent.*;

// Synthetic JDK semantics only. No application SDK or environment check.
public class OSCheckFutureVectors {
    static boolean detail;
    public static void main(String[] args) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            Future<String> future = executor.submit(() -> {
                entered.countDown();
                release.await();
                detail = true;
                return "worker-value";
            });
            if (!entered.await(5, TimeUnit.SECONDS)) throw new AssertionError("worker absent");
            try {
                future.get(0, TimeUnit.MILLISECONDS);
                throw new AssertionError("unexpected completion");
            } catch (TimeoutException expected) {
                System.out.println("timeout:done=" + future.isDone() + ":cancelled=" + future.isCancelled());
            }
            release.countDown();
            String value = future.get(5, TimeUnit.SECONDS);
            System.out.println("late:detail=" + detail + ":result=" + value);
            Future<String> failed = executor.submit(() -> { throw new UnsatisfiedLinkError("synthetic"); });
            try {
                failed.get(5, TimeUnit.SECONDS);
                throw new AssertionError("unexpected completion");
            } catch (ExecutionException expected) {
                System.out.println("worker:" + expected.getClass().getSimpleName() + ":" + expected.getCause().getClass().getSimpleName());
            }
            CountDownLatch secondEntered = new CountDownLatch(1);
            CountDownLatch secondRelease = new CountDownLatch(1);
            try {
                Future<String> second = executor.submit(() -> {
                    secondEntered.countDown();
                    secondRelease.await();
                    return "worker-value";
                });
                if (!secondEntered.await(5, TimeUnit.SECONDS)) throw new AssertionError("worker absent");
                Thread.currentThread().interrupt();
                try {
                    second.get(5, TimeUnit.SECONDS);
                    throw new AssertionError("unexpected completion");
                } catch (InterruptedException expected) {
                    System.out.println("interrupted:" + expected.getClass().getSimpleName()
                        + ":cleared=" + !Thread.currentThread().isInterrupted());
                }
                System.out.println("after-interrupt:done=" + second.isDone() + ":cancelled=" + second.isCancelled());
                secondRelease.countDown();
                System.out.println("resume:" + second.get(5, TimeUnit.SECONDS));
            } finally {
                secondRelease.countDown();
            }
        } finally {
            release.countDown();
            executor.shutdownNow(); // Test cleanup; the modeled response makes no such call.
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) throw new AssertionError("test worker alive");
        }
    }
}
