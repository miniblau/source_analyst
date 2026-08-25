package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Two-sided ground truth for the `reachable` query.
 *
 * <p>Positive and negative cases are deliberately built from the SAME sink names, so a query that
 * passes by matching sink names alone fails here: only dataflow separates them.
 */
@RestController
public class FlowController {

  private final Connection conn;

  public FlowController(Connection conn) {
    this.conn = conn;
  }

  /** POSITIVE: request parameter concatenated into SQL, one method hop to the sink. */
  public ResultSet tainted(@RequestParam String name) throws Exception {
    return runQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }

  private ResultSet runQuery(String sql) throws Exception {
    Statement st = conn.createStatement();
    return st.executeQuery(sql);
  }

  /**
   * NEGATIVE (bound parameter): the request value reaches the statement, but as a *bound value*,
   * never as statement text. Same sink names as the positive case; no flow into arg 1.
   */
  public ResultSet bound(@RequestParam String name) throws Exception {
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, name);
    return ps.executeQuery();
  }

  /** NEGATIVE (no source): SQL is concatenated, but only from constants. */
  public ResultSet constantOnly() throws Exception {
    String table = "users";
    Statement st = conn.createStatement();
    return st.executeQuery("SELECT * FROM " + table + " WHERE active = 1");
  }

  /**
   * POSITIVE, with a candidate sanitizer on the path. Still a flow: `reachable` must report it,
   * and `sanitizer_on_path` must report the escape() call sitting on it — without either query
   * deciding whether that call actually works. Effectiveness is a belief, not a query result.
   */
  public ResultSet escaped(@RequestParam String term) throws Exception {
    return runQuery("SELECT * FROM users WHERE note = '" + escape(term) + "'");
  }

  private String escape(String s) {
    return s.replace("'", "''");
  }

  /** NEGATIVE (source with no sink): an annotated source that reaches no SQL sink at all. */
  public String echo(@RequestParam String greeting) {
    return "hello " + greeting;
  }
}
