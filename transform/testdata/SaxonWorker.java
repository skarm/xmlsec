import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

// Reuse the JVM, never Saxon classes, processors or document pools. Saxon keeps
// mutable static serializer tables, so even a fresh Configuration is insufficient.
// Invoke the same CLI implementation as the one-shot oracle, with unchanged args.
// Saxon 12.10 doQuery/doTransform throw CommandExitException on failure. The
// legacy 9.4 CLI can call System.exit and deliberately remains a separate process.
class SaxonWorker {
    public static void main(String[] args) throws Exception {
        PrintStream protocol = System.out;
        PrintStream diagnostics = System.err;
        BufferedReader requests = new BufferedReader(
            new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String[] entries = System.getProperty("java.class.path").split(File.pathSeparator);
        URL[] classpath = new URL[entries.length];
        for (int i = 0; i < entries.length; i++) {
            classpath[i] = new File(entries[i]).toURI().toURL();
        }
        String request;
        while ((request = requests.readLine()) != null) {
            String[] fields = request.split("\t", -1);
            String mode = fields[0];
            String[] options = Arrays.stream(fields).skip(1)
                .map(value -> new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8))
                .toArray(String[]::new);
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int status = 0;
            ClassLoader previous = Thread.currentThread().getContextClassLoader();
            try (URLClassLoader loader = new URLClassLoader(classpath, ClassLoader.getPlatformClassLoader());
                 PrintStream out = new PrintStream(stdout, true, StandardCharsets.UTF_8);
                 PrintStream err = new PrintStream(stderr, true, StandardCharsets.UTF_8)) {
                System.setOut(out);
                System.setErr(err);
                Thread.currentThread().setContextClassLoader(loader);
                try {
                    if (!mode.equals("Query") && !mode.equals("Transform")) {
                        throw new IllegalArgumentException("unsupported oracle mode: " + mode);
                    }
                    Class<?> cli = loader.loadClass("net.sf.saxon." + mode);
                    cli.getMethod("do" + mode, String[].class, String.class)
                        .invoke(cli.getConstructor().newInstance(), options, "net.sf.saxon." + mode);
                } catch (InvocationTargetException failure) {
                    Throwable cause = failure.getCause();
                    if (cause.getClass().getName().equals("net.sf.saxon.CommandExitException")) {
                        status = (Integer) cause.getClass().getMethod("getCode").invoke(cause);
                    } else {
                        status = 1;
                        cause.printStackTrace(err);
                    }
                } catch (Exception failure) {
                    status = 1;
                    failure.printStackTrace(err);
                } finally {
                    System.setOut(protocol);
                    System.setErr(diagnostics);
                    Thread.currentThread().setContextClassLoader(previous);
                }
            }
            protocol.println(status + "\t" + Base64.getEncoder().encodeToString(stdout.toByteArray())
                + "\t" + Base64.getEncoder().encodeToString(stderr.toByteArray()));
            protocol.flush();
        }
    }
}
