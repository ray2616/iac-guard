FROM alpine:3.21.3 AS builder
RUN printf example > /example
FROM alpine:3.21.3
WORKDIR /app
COPY --from=builder /example /app/example
USER 10001
HEALTHCHECK CMD ["true"]
CMD ["true"]

