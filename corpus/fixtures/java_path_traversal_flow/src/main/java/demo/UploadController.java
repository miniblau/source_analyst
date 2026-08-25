package demo;

import java.io.File;
import java.io.IOException;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Two-sided ground truth for the `reachable` query on path_traversal.
 *
 * <p>Positive and negative cases are deliberately built from the SAME sink names, so a query that
 * passes by matching sink names alone fails here: only dataflow separates them.
 *
 * <p>The sink shape for this class is the RECEIVER, not an argument — `f.createNewFile()` carries
 * no argument at all and the tainted path lives in the object the call is made on. That is why the
 * manifest taints `arg_index: "0"`, and why this fixture would stay dark under SQLi's arg 1.
 */
@RestController
public class UploadController {

  private final String home;

  public UploadController(String home) {
    this.home = home;
  }

  /** POSITIVE: request parameter becomes the filename, one method hop to the sink. */
  public void upload(@RequestParam String name) throws IOException {
    create(new File(new File(home, "uploads"), name));
  }

  private void create(File f) throws IOException {
    f.createNewFile();
  }

  /**
   * POSITIVE, with a candidate sanitizer on the path. Still a flow: `reachable` must report it and
   * `sanitizer_on_path` must report the strip() call sitting on it — without either query deciding
   * whether that call actually works. Effectiveness is a belief, not a query result.
   *
   * <p>Modelled on WebGoat's ProfileUploadFix, and bypassable the same way: replacing "../" once
   * leaves "....//" intact, which reconstitutes the traversal.
   */
  public void uploadStripped(@RequestParam String name) throws IOException {
    create(new File(new File(home, "uploads"), strip(name)));
  }

  private String strip(String s) {
    return s.replace("../", "");
  }

  /** NEGATIVE (no source): same sink name, filename is a literal — nothing flows into it. */
  public void uploadFixed() throws IOException {
    create(new File(new File(home, "uploads"), "fixed.txt"));
  }

  /** NEGATIVE (source with no sink): an annotated source that reaches no filesystem sink at all. */
  public String echo(@RequestParam String greeting) {
    return "hello " + greeting;
  }
}
