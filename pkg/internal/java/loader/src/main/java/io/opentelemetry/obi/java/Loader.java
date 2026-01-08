/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;

public class Loader {
  public static void agentCaller(String function, String agentArgs, Instrumentation inst) {
    String agentResourcePath = "agent/agent.zip";

    try {
      Class.forName("io.opentelemetry.obi.java.Agent", false, Loader.class.getClassLoader());
      System.err.println("agent already loaded, ignoring load request.");
      return;
    } catch (ClassNotFoundException ignore) {
    }

    File tempAgentJar;
    try (InputStream agentJarStream =
        Loader.class.getClassLoader().getResourceAsStream(agentResourcePath)) {
      if (agentJarStream == null) {
        throw new FileNotFoundException("Resource not found: " + agentResourcePath);
      }

      tempAgentJar = Files.createTempFile("agent", ".jar").toFile();
      tempAgentJar.deleteOnExit();
      try (OutputStream out = Files.newOutputStream(tempAgentJar.toPath())) {
        byte[] buffer = new byte[8192];
        int len;
        while ((len = agentJarStream.read(buffer)) != -1) {
          out.write(buffer, 0, len);
        }
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    try {
      URL agentJarUrl = tempAgentJar.toURI().toURL();
      try (URLClassLoader agentClassLoader =
          new URLClassLoader(new URL[] {agentJarUrl}, Loader.class.getClassLoader())) {
        Class<?> mainClass = agentClassLoader.loadClass("io.opentelemetry.obi.java.Agent");

        java.lang.reflect.Method mainMethod =
            mainClass.getMethod(function, String.class, Instrumentation.class);
        mainMethod.invoke(null, agentArgs, inst);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static void premain(String agentArgs, Instrumentation inst) {
    agentCaller("premain", agentArgs, inst);
  }

  public static void agentmain(String args, Instrumentation inst) {
    agentCaller("agentmain", args, inst);
  }

  // Just a test method functionality, not used in the Agent
  public static void main(String[] args) {
    premain(null, null);
  }
}
