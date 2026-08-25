package demo;

import java.util.Map;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * Two-sided ground truth for the `reachable` query on open_redirect.
 *
 * <p>Both sides construct the SAME sink from the SAME annotated source and BOTH produce a flow, so
 * a query that passes by matching sink names alone fails here and so does one that assumes any
 * reported flow is a bug. What separates them is not the sink and not the presence of a flow — it
 * is what the tainted value *becomes* on the way.
 *
 * <p>Modelled on WebGoat's OpenRedirectRealRedirect / OpenRedirectSecureController pair, which is
 * the only place in the corpus where a labelled NEGATIVE exists for any class.
 */
@RestController
public class RedirectController {

  // Only these destinations are reachable through the safe endpoint.
  private static final Map<Integer, String> DESTINATIONS =
      Map.of(1, "/welcome", 2, "/login", 3, "/logout");

  /** POSITIVE: the caller's text becomes the destination. */
  public ModelAndView open(@RequestParam String url) {
    return new ModelAndView("redirect:" + url);
  }

  /**
   * NEGATIVE, and the interesting one: the flow is REAL and must be reported, but the tainted value
   * is an Integer used as a KEY. What reaches the sink came out of a fixed table, so the caller
   * chooses among three internal paths and nothing else.
   *
   * <p>Note the discriminator is the SOURCE type and the lookup step, not the sink's argument type
   * — that is `java.lang.String` on both sides, because it describes the concatenation result.
   */
  public ModelAndView safe(@RequestParam Integer destId) {
    String dest = DESTINATIONS.getOrDefault(destId, "/welcome");
    return new ModelAndView("redirect:" + dest);
  }

  /** NEGATIVE (no source): a fixed view name, which is not a redirect at all. */
  public ModelAndView home() {
    return new ModelAndView("home");
  }
}
