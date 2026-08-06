package com.bachelor.toolbox.common;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.ai.AiAgentRequest;
import com.bachelor.toolbox.ai.AiAnswerRequest;
import com.bachelor.toolbox.ai.AiPlanRequest;
import com.bachelor.toolbox.auth.ChangePasswordRequest;
import com.bachelor.toolbox.auth.LoginRequest;
import com.bachelor.toolbox.operation.SecurityActionDtos;
import com.bachelor.toolbox.postscan.PostScanConfirmRequest;
import com.bachelor.toolbox.postscan.PostScanPathRequest;
import com.bachelor.toolbox.probe.ProbeRequest;
import com.bachelor.toolbox.project.ProjectDtos;
import com.bachelor.toolbox.recon.ReconRequest;
import com.bachelor.toolbox.schedule.CreateScheduleRequest;
import com.bachelor.toolbox.target.TargetRequest;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.traffic.TrafficDtos;
import com.bachelor.toolbox.vulnerability.ActiveScanRequest;
import jakarta.validation.Constraint;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class RequestValidationMessageTests {
  private static final List<Class<?>> REQUEST_TYPES =
      List.of(
          AiAgentRequest.class,
          AiAnswerRequest.class,
          AiPlanRequest.class,
          ChangePasswordRequest.class,
          LoginRequest.class,
          SecurityActionDtos.Create.class,
          SecurityActionDtos.Decision.class,
          SecurityActionDtos.Complete.class,
          SecurityActionDtos.Rollback.class,
          PostScanConfirmRequest.class,
          PostScanPathRequest.class,
          ProbeRequest.class,
          ProjectDtos.Create.class,
          ProjectDtos.Update.class,
          ProjectDtos.Status.class,
          ReconRequest.class,
          CreateScheduleRequest.class,
          TargetRequest.class,
          CreateTaskRequest.class,
          TrafficDtos.StartRequest.class,
          TrafficDtos.DecisionRequest.class,
          ActiveScanRequest.class);

  @Test
  void everyStandaloneRequestConstraintDeclaresAChineseMessage() {
    List<String> unlocalizedConstraints = new ArrayList<>();
    int constraintCount = 0;

    for (Class<?> requestType : REQUEST_TYPES) {
      for (Field field : requestType.getDeclaredFields()) {
        if (Modifier.isStatic(field.getModifiers())) {
          continue;
        }
        String fieldPath = requestType.getSimpleName() + "." + field.getName();
        constraintCount +=
            inspectAnnotations(field.getDeclaredAnnotations(), fieldPath, unlocalizedConstraints);
        constraintCount +=
            inspectNestedTypes(field.getAnnotatedType(), fieldPath, unlocalizedConstraints);
      }
    }

    assertThat(constraintCount).isPositive();
    assertThat(unlocalizedConstraints).as("请求 DTO 的 Bean Validation 提示必须显式使用中文").isEmpty();
  }

  private static int inspectNestedTypes(
      AnnotatedType type, String path, List<String> unlocalizedConstraints) {
    if (type instanceof AnnotatedParameterizedType parameterizedType) {
      int count = 0;
      AnnotatedType[] arguments = parameterizedType.getAnnotatedActualTypeArguments();
      for (int index = 0; index < arguments.length; index++) {
        AnnotatedType argument = arguments[index];
        String argumentPath = path + "<" + index + ">";
        count +=
            inspectAnnotations(argument.getAnnotations(), argumentPath, unlocalizedConstraints);
        count += inspectNestedTypes(argument, argumentPath, unlocalizedConstraints);
      }
      return count;
    }
    if (type instanceof AnnotatedArrayType arrayType) {
      AnnotatedType componentType = arrayType.getAnnotatedGenericComponentType();
      int count =
          inspectAnnotations(componentType.getAnnotations(), path + "[]", unlocalizedConstraints);
      return count + inspectNestedTypes(componentType, path + "[]", unlocalizedConstraints);
    }
    return 0;
  }

  private static int inspectAnnotations(
      Annotation[] annotations, String path, List<String> unlocalizedConstraints) {
    int count = 0;
    for (Annotation annotation : annotations) {
      if (!annotation.annotationType().isAnnotationPresent(Constraint.class)) {
        continue;
      }
      count++;
      String message = constraintMessage(annotation);
      if (!containsChinese(message)) {
        unlocalizedConstraints.add(
            path + " @" + annotation.annotationType().getSimpleName() + ": " + message);
      }
    }
    return count;
  }

  private static String constraintMessage(Annotation annotation) {
    try {
      return (String) annotation.annotationType().getMethod("message").invoke(annotation);
    } catch (ReflectiveOperationException exception) {
      throw new AssertionError("无法读取校验注解的 message 属性", exception);
    }
  }

  private static boolean containsChinese(String value) {
    return value != null
        && value
            .codePoints()
            .anyMatch(
                codePoint -> Character.UnicodeScript.of(codePoint) == Character.UnicodeScript.HAN);
  }
}
