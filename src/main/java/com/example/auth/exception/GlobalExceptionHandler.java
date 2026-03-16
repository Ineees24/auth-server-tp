package com.example.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String TIMESTAMP = "timestamp";
    private static final String STATUS    = "status";
    private static final String ERROR     = "error";
    private static final String MESSAGE   = "message";
    private static final String PATH      = "path";

    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidInput(
            InvalidInputException e, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                TIMESTAMP, LocalDateTime.now().toString(),
                STATUS, 400,
                ERROR, "Bad Request",
                MESSAGE, e.getMessage(),
                PATH, req.getRequestURI()
        ));
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<Map<String, Object>> handleAuthFailed(
            AuthenticationFailedException e, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                TIMESTAMP, LocalDateTime.now().toString(),
                STATUS, 401,
                ERROR, "Unauthorized",
                MESSAGE, e.getMessage(),
                PATH, req.getRequestURI()
        ));
    }

    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(
            ResourceConflictException e, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                TIMESTAMP, LocalDateTime.now().toString(),
                STATUS, 409,
                ERROR, "Conflict",
                MESSAGE, e.getMessage(),
                PATH, req.getRequestURI()
        ));
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<Map<String, Object>> handleLocked(
            AccountLockedException e, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
                TIMESTAMP, LocalDateTime.now().toString(),
                STATUS, 429,
                ERROR, "Too Many Requests",
                MESSAGE, e.getMessage(),
                PATH, req.getRequestURI()
        ));
    }
}