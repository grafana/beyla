/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.util.concurrent.Callable;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class CallableInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(Callable.class);
  }

  public static boolean matches(Class<?> clazz) {
    return Callable.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(CallableAdvice.class)
                .on(
                    ElementMatchers.named("call")
                        .and(
                            ElementMatchers.takesArguments(0)
                                .and(ElementMatchers.isPublic())
                                .and(
                                    ElementMatchers.returns(
                                        Object.class)) // Callable.call() returns V
                                .and(
                                    ElementMatchers.isDeclaredBy(
                                        ElementMatchers.isSubTypeOf(Callable.class))))));
  }

  @SuppressWarnings("unused")
  public static final class CallableAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Callable<?> task) {
      Long parentId = SSLStorage.parentThreadId(task);
      if (parentId != null) {
        long threadId = Agent.CLibrary.INSTANCE.gettid();
        if (SSLStorage.bootDebugOn().equals(true)) {
          System.err.println(
              "[CallableAdvice] task = "
                  + task.hashCode()
                  + ", parent = "
                  + parentId
                  + ", thread = "
                  + threadId);
        }
        if (parentId != threadId) {
          Pointer p = new Memory(IOCTLPacket.packetPrefixSize);
          int wOff = IOCTLPacket.writePacket(p, 0, OperationType.THREAD, parentId);
          Agent.CLibrary.INSTANCE.ioctl(0, Agent.IOCTL_CMD, Pointer.nativeValue(p));
        }
      }
      SSLStorage.untrackTask(task);
    }
  }
}
