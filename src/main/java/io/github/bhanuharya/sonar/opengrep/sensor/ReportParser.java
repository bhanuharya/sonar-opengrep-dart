package io.github.bhanuharya.sonar.opengrep.sensor;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Reads the two report formats the plugin understands:
 *
 * <ul>
 *   <li>OpenGrep / Semgrep JSON ({@code opengrep scan --json}): a top-level {@code results} array;</li>
 *   <li>SDT canonical findings ({@code findings.json}): a top-level {@code findings} array, of which
 *       only the {@code opengrep} adapter's findings are taken — other scanners' findings have their
 *       own importers.</li>
 * </ul>
 */
public final class ReportParser {

  private ReportParser() {
  }

  public static List<ReportFinding> parse(Path report) throws IOException {
    try (Reader reader = Files.newBufferedReader(report, StandardCharsets.UTF_8)) {
      JsonElement root = JsonParser.parseReader(reader);
      if (!root.isJsonObject()) {
        throw new IOException("not a JSON object: " + report);
      }
      JsonObject doc = root.getAsJsonObject();
      if (doc.has("results") && doc.get("results").isJsonArray()) {
        return openGrep(doc.getAsJsonArray("results"));
      }
      if (doc.has("findings") && doc.get("findings").isJsonArray()) {
        return sdt(doc.getAsJsonArray("findings"));
      }
      throw new IOException("neither an OpenGrep report (results) nor SDT findings (findings): " + report);
    } catch (RuntimeException e) {
      throw new IOException("cannot parse " + report + ": " + e.getMessage(), e);
    }
  }

  private static List<ReportFinding> openGrep(JsonArray results) {
    List<ReportFinding> findings = new ArrayList<>();
    for (JsonElement element : results) {
      JsonObject result = element.getAsJsonObject();
      JsonObject extra = object(result, "extra");
      JsonObject metadata = object(extra, "metadata");
      String category = string(metadata, "category");
      findings.add(new ReportFinding(string(result, "check_id"), string(result, "path"),
        integer(object(result, "start"), "line"), integer(object(result, "end"), "line"),
        string(extra, "message"), string(extra, "severity"),
        "security".equalsIgnoreCase(category) || metadata.has("cwe")));
    }
    return findings;
  }

  private static List<ReportFinding> sdt(JsonArray items) {
    List<ReportFinding> findings = new ArrayList<>();
    for (JsonElement element : items) {
      JsonObject finding = element.getAsJsonObject();
      String adapter = string(object(finding, "scanner"), "adapter");
      if (!"opengrep".equals(adapter.toLowerCase(Locale.ROOT))) {
        continue;
      }
      JsonObject location = object(finding, "location");
      JsonObject rule = object(finding, "rule");
      findings.add(new ReportFinding(string(rule, "id"), string(location, "path"),
        integer(location, "startLine"), integer(location, "endLine"),
        string(finding, "message"), string(object(finding, "severity"), "canonical"),
        true));
    }
    return findings;
  }

  private static JsonObject object(JsonObject parent, String key) {
    JsonElement value = parent == null ? null : parent.get(key);
    return value != null && value.isJsonObject() ? value.getAsJsonObject() : new JsonObject();
  }

  private static String string(JsonObject parent, String key) {
    JsonElement value = parent.get(key);
    return value != null && value.isJsonPrimitive() ? value.getAsString() : "";
  }

  private static int integer(JsonObject parent, String key) {
    JsonElement value = parent.get(key);
    try {
      return value != null && value.isJsonPrimitive() ? value.getAsInt() : 0;
    } catch (NumberFormatException e) {
      return 0;
    }
  }
}
