package io.github.bhanuharya.sonar.opengrep;

import io.github.bhanuharya.sonar.opengrep.rules.OpenGrepProfilesDefinition;
import io.github.bhanuharya.sonar.opengrep.rules.OpenGrepRulesDefinition;
import io.github.bhanuharya.sonar.opengrep.sensor.OpenGrepSensor;
import org.sonar.api.Plugin;

/**
 * OpenGrep for SonarQube.
 *
 * <p>The server side turns OpenGrep/Semgrep rule YAML into native Sonar rules (one
 * repository per installed language), typed as Vulnerability or Security Hotspot and
 * mapped to CWE/OWASP. The scanner side imports OpenGrep results against those rules.
 */
public class OpenGrepPlugin implements Plugin {

  @Override
  public void define(Context context) {
    context.addExtensions(OpenGrepProperties.definitions());
    context.addExtensions(OpenGrepRulesDefinition.class, OpenGrepProfilesDefinition.class, OpenGrepSensor.class);
  }
}
