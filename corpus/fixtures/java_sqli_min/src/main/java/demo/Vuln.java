package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

/** Two-sided ground truth for the sql_sinks query: one planted sink, one control. */
public class Vuln {

  /** POSITIVE: sink call whose SQL argument is a runtime concatenation. */
  public void concatenated(Connection c, String name) throws Exception {
    Statement st = c.createStatement();
    st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }

  /** NEGATIVE: same sink name, parameterized — the SQL text is a literal. */
  public void parameterized(Connection c, String name) throws Exception {
    PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, name);
    ps.executeQuery();
  }

  /** NEGATIVE: no SQL sink at all. */
  public String greet(String name) {
    return "hello " + name;
  }
}
