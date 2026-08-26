package demo;

import java.nio.file.Files;
import java.nio.file.Paths;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Idioms an ordinary Java shop actually uses. Every method here is a live bug, and
 * NONE of these shapes occurs anywhere in WebGoat.
 *
 * <p>This fixture exists because the corpus is one small, deliberately vulnerable
 * teaching app, and a class validated only against it can be perfectly scored and
 * still blind. Measured 2026-08-26: with `path_traversal` pinned to the receiver —
 * the shape WebGoat happens to use — {@code Files.readAllBytes} here produced ZERO
 * flows while precision and recall on WebGoat read 1.0 throughout.
 *
 * <p>Every sink below is reached by a manifest entry that no corpus run had ever
 * exercised. Adding a sink name is cheap; proving it matches something is not, and
 * this is where that gets proved.
 */
@RestController
public class Typical {
  private JdbcTemplate jdbc;
  private EntityManager em;

  // SQLi via Spring JdbcTemplate — the most common enterprise DAO layer.
  public Object jdbcTemplate(@RequestParam String name) {
    return jdbc.queryForList("select * from users where name = '" + name + "'");
  }

  // SQLi via JPA.
  public Object jpa(@RequestParam String name) {
    return em.createQuery("select u from User u where u.name = '" + name + "'").getResultList();
  }

  // Path traversal via the static NIO API — taint in argument 1, not the receiver.
  public byte[] nio(@RequestParam String p) throws Exception {
    return Files.readAllBytes(Paths.get("/var/data/" + p));
  }

  // Open redirect via the servlet API — the canonical Java form.
  public void redirect(@RequestParam String url, HttpServletResponse resp) throws Exception {
    resp.sendRedirect(url);
  }
}
