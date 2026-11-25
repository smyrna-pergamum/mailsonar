// Never infer the analyst machine's timezone for forensic correlations.
export function eventTime(value) {
 if (typeof value !== 'string' || !/(?:Z|[+-]\d{2}:?\d{2})$/i.test(value.trim())) return NaN;
 return Date.parse(value);
}
export function timeQuality(events) {
 return {
  missing: events.filter(e=>!e.timestamp?.trim()).length,
  ambiguous: events.filter(e=>e.timestamp?.trim()&&!Number.isFinite(eventTime(e.timestamp))).length
 };
}
