package io.github.bhanuharya.sonar.opengrep.rules;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Reads OpenGrep/Semgrep rule YAML: the pack bundled in the plugin jar, and any
 * directories an administrator configures. A file that is not a rule file (no
 * top-level {@code rules:} list) is skipped, and a malformed one is logged and
 * skipped, so one bad file never takes the server down.
 */
public final class RuleLoader {

  private static final Logger LOG = Loggers.get(RuleLoader.class);
  static final String BUNDLED_ROOT = "opengrep-rules/";

  private RuleLoader() {
  }

  /** The rules bundled under {@code opengrep-rules/} in the plugin jar (or classes dir in tests). */
  public static List<OpenGrepRule> bundled() {
    List<OpenGrepRule> rules = new ArrayList<>();
    CodeSource code = RuleLoader.class.getProtectionDomain().getCodeSource();
    if (code == null) {
      return rules;
    }
    try {
      Path location = Path.of(code.getLocation().toURI());
      if (Files.isDirectory(location)) {
        rules.addAll(directory(location.resolve(BUNDLED_ROOT)));
      } else {
        rules.addAll(jar(location));
      }
    } catch (URISyntaxException | IOException e) {
      LOG.warn("OpenGrep: cannot read the bundled rule pack: {}", e.getMessage());
    }
    return rules;
  }

  /** Every rule in every .yaml/.yml file under a directory, in path order. */
  public static List<OpenGrepRule> directory(Path root) {
    if (!Files.isDirectory(root)) {
      LOG.warn("OpenGrep: rule directory {} does not exist", root);
      return List.of();
    }
    List<OpenGrepRule> rules = new ArrayList<>();
    try (Stream<Path> files = Files.walk(root)) {
      for (Path file : files.filter(RuleLoader::isYaml).sorted().toList()) {
        try (InputStream in = Files.newInputStream(file)) {
          rules.addAll(parse(in, root.relativize(file).toString()));
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return rules;
  }

  private static List<OpenGrepRule> jar(Path jarPath) throws IOException {
    List<OpenGrepRule> rules = new ArrayList<>();
    try (JarFile jar = new JarFile(jarPath.toFile())) {
      List<JarEntry> entries = new ArrayList<>();
      for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements(); ) {
        JarEntry entry = e.nextElement();
        if (entry.getName().startsWith(BUNDLED_ROOT) && isYaml(Path.of(entry.getName()))) {
          entries.add(entry);
        }
      }
      entries.sort((a, b) -> a.getName().compareTo(b.getName()));
      for (JarEntry entry : entries) {
        try (InputStream in = jar.getInputStream(entry)) {
          rules.addAll(parse(in, entry.getName().substring(BUNDLED_ROOT.length())));
        }
      }
    }
    return rules;
  }

  private static boolean isYaml(Path path) {
    String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
    return name.endsWith(".yaml") || name.endsWith(".yml");
  }

  /** The rules in one YAML document; empty when it is not a rule file or cannot be parsed. */
  public static List<OpenGrepRule> parse(InputStream in, String source) {
    Object document;
    try {
      document = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
    } catch (RuntimeException e) {
      LOG.warn("OpenGrep: skipping {}: not valid YAML ({})", source, e.getMessage());
      return List.of();
    }
    if (!(document instanceof Map<?, ?> top) || !(top.get("rules") instanceof List<?> list)) {
      return List.of();
    }
    List<OpenGrepRule> rules = new ArrayList<>();
    for (Object item : list) {
      if (item instanceof Map<?, ?> raw) {
        OpenGrepRule rule = toRule(raw, source);
        if (rule != null) {
          rules.add(rule);
        }
      }
    }
    return rules;
  }

  private static OpenGrepRule toRule(Map<?, ?> raw, String source) {
    Object id = raw.get("id");
    if (id == null || id.toString().isBlank()) {
      LOG.warn("OpenGrep: skipping a rule without an id in {}", source);
      return null;
    }
    Map<String, Object> metadata = new LinkedHashMap<>();
    if (raw.get("metadata") instanceof Map<?, ?> meta) {
      meta.forEach((key, value) -> metadata.put(String.valueOf(key), value));
    }
    List<String> includes = List.of();
    if (raw.get("paths") instanceof Map<?, ?> paths && paths.get("include") instanceof Collection<?> globs) {
      includes = globs.stream().map(String::valueOf).toList();
    }
    List<String> languages = raw.get("languages") instanceof Collection<?> langs
      ? langs.stream().map(lang -> String.valueOf(lang).toLowerCase(Locale.ROOT)).toList()
      : List.of();
    return new OpenGrepRule(id.toString().trim(), stringOr(raw.get("message"), ""),
      stringOr(raw.get("severity"), "WARNING").toUpperCase(Locale.ROOT), languages, metadata, includes,
      "taint".equals(raw.get("mode")), source);
  }

  private static String stringOr(Object value, String fallback) {
    return value == null ? fallback : value.toString().trim();
  }
}
