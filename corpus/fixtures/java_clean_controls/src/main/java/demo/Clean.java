package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The negative control: code that is safe BY CONSTRUCTION, plus deliberate
 * name-collision bait.
 *
 * <p>Every class should report ZERO flows here. That is the point — WebGoat is
 * ~all-vulnerable, so precision on it is measured against almost nothing, and the
 * false-positive rate on ordinary safe code was simply never measured. Any flow
 * this fixture produces is a substrate false positive with a name and a line.
 *
 * <p>Safe by CONSTRUCTION, never by sanitizer. A sanitizer on the path is still a
 * flow and `reachable` is right to report it — effectiveness is a belief, not a
 * query result — so a fixture full of escaping calls would prove nothing. Here the
 * untrusted value never becomes the dangerous part: it is bound as a parameter,
 * used as a lookup key, or simply not used at all.
 */
@RestController
public class Clean {

  private static final Map<Integer, String> DESTINATIONS =
      Map.of(1, "/welcome", 2, "/login");

  /** SAFE: the value is BOUND, never statement text. */
  public void boundParameter(Connection c, @RequestParam String name) throws Exception {
    PreparedStatement ps = c.prepareStatement("select * from users where name = ?");
    ps.setString(1, name);
    ps.executeQuery();
  }

  /** SAFE: the caller picks a key, not a destination. */
  public String allowlistedRedirect(@RequestParam Integer destId, HttpServletResponse r)
      throws Exception {
    r.sendRedirect(DESTINATIONS.getOrDefault(destId, "/welcome"));
    return "ok";
  }

  /** SAFE: the filename is fixed; the request value only decides whether to act. */
  public boolean fixedPath(@RequestParam boolean wanted) {
    return wanted && new java.io.File("/var/data/report.txt").exists();
  }

  // ---- name-collision bait -------------------------------------------------
  // These must be CALLS, not just declarations: sinks match call nodes, so a
  // method merely named `execute` bites nothing. The first version of this fixture
  // declared them without calling them and measured a false-positive rate of zero
  // that it had not earned. This is WebGoat's ProfileUploadBase.execute collision
  // reproduced deliberately, for every class we model.

  /** `execute` is in the sqli sink list. This one runs a task. */
  public void runsATask(@RequestParam String jobName) {
    tasks().execute(jobName);
  }

  /** `copy` is in the path_traversal sink list. This one copies bytes. */
  public void copiesBytes(@RequestParam String payload) {
    buffers().copy(payload, 0);
  }

  /** `setHeader` is in the open_redirect sink list. This one builds a JWT header. */
  public void signsAToken(@RequestParam String claim) {
    jws().setHeader("kid", claim);
  }

  private TaskRunner tasks() { return new TaskRunner(); }
  private Buffers buffers() { return new Buffers(); }
  private Signer jws() { return new Signer(); }

  static class TaskRunner { void execute(String job) {} }
  static class Buffers { void copy(String data, int at) {} }
  static class Signer { void setHeader(String k, String v) {} }
}
