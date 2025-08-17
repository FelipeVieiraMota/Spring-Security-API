package com.motavieirafelipe.authorization.domain.dto;

import java.time.LocalDateTime;

public record ErrorResponseDto (
    LocalDateTime timestamp,
    int status,
    String error,
    String message
) {
    @Override
    public String toString()
    {
        return String.format
        (
            """
                {
                    "timestamp": %s,
                    "status": "%s",
                    "error": "%s",
                    "message": %s
                }
            """,
            timestamp,
            status,
            error,
            message
        );
    }
}
