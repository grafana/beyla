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
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.Future;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class JavaExecutorInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(Executor.class);
  }

  public static boolean matches(Class<?> clazz) {
    return Executor.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(SetExecuteRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.named("execute")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))))
            .visit(
                Advice.to(SetExecuteRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.named("addTask")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))))
            .visit(
                Advice.to(SetJavaForkJoinStateAdvice.class)
                    .on(
                        ElementMatchers.named("execute")
                            .and(ElementMatchers.takesArgument(0, ForkJoinTask.class))))
            .visit(
                Advice.to(SetJavaForkJoinStateAdvice.class)
                    .on(
                        ElementMatchers.named("submit")
                            .and(ElementMatchers.takesArgument(0, ForkJoinTask.class))))
            .visit(
                Advice.to(SetJavaForkJoinStateAdvice.class)
                    .on(
                        ElementMatchers.named("invoke")
                            .and(ElementMatchers.takesArgument(0, ForkJoinTask.class))))
            .visit(
                Advice.to(SetSubmitRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.named("submit")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(SetSubmitRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.named("schedule")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(SetCallableStateAdvice.class)
                    .on(
                        ElementMatchers.named("submit")
                            .and(ElementMatchers.takesArgument(0, Callable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(SetCallableStateAdvice.class)
                    .on(
                        ElementMatchers.named("schedule")
                            .and(ElementMatchers.takesArgument(0, Callable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(SetCallableStateForCallableCollectionAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("invokeAny", "invokeAll")
                            .and(ElementMatchers.takesArgument(0, Collection.class))));
  }

  @SuppressWarnings("unused")
  public static final class SetExecuteRunnableStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enterJobSubmit(
        @Advice.Argument(value = 0, readOnly = false) Runnable task, @Advice.Origin String method) {
      long threadId = Agent.CLibrary.INSTANCE.gettid();
      Long parentId = SSLStorage.parentThreadId(task);
      if (parentId != null) {
        if (SSLStorage.bootDebugOn().equals(true)) {
          System.err.println(
              "[SetExecuteRunnableStateAdvice] task = "
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

      SSLStorage.trackTask(threadId, task);
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetExecuteRunnableStateAdvice] "
                + "("
                + method
                + ")"
                + +threadId
                + " enter jobSubmit task = "
                + task.hashCode());
      }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(0) Runnable task, @Advice.Thrown Throwable throwable) {
      if (throwable != null) {
        SSLStorage.untrackTask(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class SetJavaForkJoinStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enterJobSubmit(
        @Advice.Argument(0) ForkJoinTask<?> task, @Advice.Origin String method) {
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetJavaForkJoinStateAdvice] ("
                + method
                + ") enter jobSubmit task = "
                + task.hashCode());
      }
      long threadId = Agent.CLibrary.INSTANCE.gettid();
      SSLStorage.trackTask(threadId, task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(0) ForkJoinTask<?> task, @Advice.Thrown Throwable throwable) {
      if (throwable != null) {
        SSLStorage.untrackTask(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static class SetSubmitRunnableStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enterJobSubmit(@Advice.Argument(value = 0, readOnly = false) Runnable task) {
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetSubmitRunnableStateAdvice] enter jobSubmit task = " + task.hashCode());
      }
      long threadId = Agent.CLibrary.INSTANCE.gettid();
      SSLStorage.trackTask(threadId, task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(0) Runnable task,
        @Advice.Thrown Throwable throwable,
        @Advice.Return Future<?> future) {
      if (throwable != null) {
        SSLStorage.untrackTask(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static class SetCallableStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enterJobSubmit(
        @Advice.Argument(0) Callable<?> task, @Advice.Origin String method) {
      long threadId = Agent.CLibrary.INSTANCE.gettid();
      Long parentId = SSLStorage.parentThreadId(task);
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetCallableStateAdvice] task = "
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
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetCallableStateAdvice] (" + method + ") enter jobSubmit task = " + task.hashCode());
      }
      SSLStorage.trackTask(threadId, task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(0) Callable<?> task,
        @Advice.Thrown Throwable throwable,
        @Advice.Return Future<?> future) {
      if (throwable != null) {
        SSLStorage.untrackTask(task);
      }

      try {
        if (future != null) {
          long threadId = Agent.CLibrary.INSTANCE.gettid();
          SSLStorage.trackTask(threadId, future);
          if (SSLStorage.bootDebugOn().equals(true)) {
            System.err.println(
                "[SetCallableStateAdvice] exit jobSubmit return task = "
                    + future.hashCode()
                    + ", thread = "
                    + threadId);
          }
        }
      } catch (Throwable t) {
        t.printStackTrace();
      }
    }
  }

  @SuppressWarnings("unused")
  public static class SetCallableStateForCallableCollectionAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Collection<?> submitEnter(
        @Advice.Argument(0) Collection<? extends Callable<?>> tasks) {
      if (tasks == null) {
        return Collections.emptyList();
      }

      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetCallableStateForCallableCollectionAdvice] enter jobSubmit tasks = "
                + tasks.hashCode());
      }

      long threadId = Agent.CLibrary.INSTANCE.gettid();
      for (Callable<?> task : tasks) {
        SSLStorage.trackTask(threadId, task);
      }

      return tasks;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void submitExit(
        @Advice.Enter Collection<? extends Callable<?>> tasks, @Advice.Thrown Throwable throwable) {
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetCallableStateForCallableCollectionAdvice] exit jobSubmit tasks = "
                + tasks.hashCode());
      }
      if (throwable != null) {
        for (Callable<?> task : tasks) {
          SSLStorage.untrackTask(task);
        }
      }
    }
  }
}
