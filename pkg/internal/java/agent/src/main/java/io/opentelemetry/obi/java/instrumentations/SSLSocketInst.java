/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.ebpf.ProxyInputStream;
import io.opentelemetry.obi.java.ebpf.ProxyOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import javax.net.ssl.SSLSocket;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class SSLSocketInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(SSLSocket.class)
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
        .and(ElementMatchers.not(ElementMatchers.isInterface()));
  }

  public static boolean matches(Class<?> clazz) {
    return SSLSocket.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(GetOutputStreamAdvice.class).on(ElementMatchers.named("getOutputStream")))
            .visit(
                Advice.to(GetInputStreamAdvice.class).on(ElementMatchers.named("getInputStream")));
  }

  public static final class GetOutputStreamAdvice {
    @Advice.OnMethodExit // (suppress = Throwable.class)
    public static void getOutputStream(
        @Advice.This final SSLSocket socket,
        @Advice.Return(readOnly = false) OutputStream returnValue) {
      returnValue = new ProxyOutputStream(returnValue, socket);
    }
  }

  public static final class GetInputStreamAdvice {
    @Advice.OnMethodExit // (suppress = Throwable.class)
    public static void getInputStream(
        @Advice.This final SSLSocket socket,
        @Advice.Return(readOnly = false) InputStream returnValue) {
      returnValue = new ProxyInputStream(returnValue, socket);
    }
  }
}
