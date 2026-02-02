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
import java.util.concurrent.ForkJoinTask;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class JavaForkJoinTaskInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(ForkJoinTask.class);
  }

  public static boolean matches(Class<?> clazz) {
    return ForkJoinTask.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(ForkJoinTaskAdvice.class)
                    .on(
                        ElementMatchers.named("exec")
                            .and(
                                ElementMatchers.takesArguments(0)
                                    .and(ElementMatchers.not(ElementMatchers.isAbstract())))))
            .visit(
                Advice.to(ForkJoinTaskAdvice.class)
                    .on(
                        ElementMatchers.named("doExec")
                            .and(
                                ElementMatchers.takesArguments(0)
                                    .and(ElementMatchers.not(ElementMatchers.isAbstract())))))
            .visit(
                Advice.to(ForkAdvice.class)
                    .on(ElementMatchers.named("fork").and(ElementMatchers.takesArguments(0))));
  }

  @SuppressWarnings("unused")
  public static final class ForkAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enterJobSubmit(@Advice.This ForkJoinTask<?> task) {
      long threadId = Agent.CLibrary.INSTANCE.gettid();
      SSLStorage.trackTask(threadId, task);
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println("[ForkAdvice] " + threadId + "fork task = " + task.hashCode());
      }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.This ForkJoinTask<?> task, @Advice.Thrown Throwable throwable) {
      if (throwable != null) {
        SSLStorage.untrackTask(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class ForkJoinTaskAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enterJobSubmit(
        @Advice.This ForkJoinTask<?> task, @Advice.Origin String method) {
      Long parentId = SSLStorage.parentThreadId(task);
      long threadId = Agent.CLibrary.INSTANCE.gettid();
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[ForkJoinTaskAdvice] ("
                + method
                + ") exec task = "
                + task.hashCode()
                + ", parent = "
                + parentId
                + ", thread = "
                + threadId);
      }
      if (parentId != null && parentId != threadId) {
        Pointer p = new Memory(IOCTLPacket.packetPrefixSize);
        int wOff = IOCTLPacket.writePacket(p, 0, OperationType.THREAD, parentId);
        Agent.CLibrary.INSTANCE.ioctl(0, Agent.IOCTL_CMD, Pointer.nativeValue(p));
      }
      SSLStorage.untrackTask(task);
    }
  }
}
