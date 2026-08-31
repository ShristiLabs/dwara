# Observability and analytics

Two complementary views onto your traffic. Observability answers "is it
healthy right now" - the live signals (logs, metrics, request IDs,
error envelopes) an operator uses during an incident. Analytics answers
"what happened over time, to whom, and why" - the durable, queryable
history used after the fact. The two are independent: run either, both,
or neither.

Alert webhooks sit alongside these as the push channel for gateway
state changes (breaker trips, endpoint ejections, config publishes).

## In this section

- [Observability](./observability) - structured logs, request IDs, the
  metrics families, SLOs and error budgets, and the JSON error envelope.
- [Analytics](./analytics) - the embedded analytics store: durable
  traffic history with rollups, retention, and bounded disk usage.
- [Analytics stream](./analytics-stream) - the opt-in raw firehose out
  to an external HTTP collector, fire-and-forget end to end.
- [Alert and event webhooks](./webhooks) - POST JSON notifications on
  gateway state changes to your incident tool or collector.
