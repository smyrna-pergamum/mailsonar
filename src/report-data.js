import {eventTime,timeQuality} from './event-time.js';
import {hourlyBuckets,severityCounts} from './nightwire-data.js';
import {correlate} from './analysis.js';
import {feedbackMetrics} from './feedback.js';

export function reportAnalysis(events,findings,feedback=[]) {
 const times=events.map(e=>eventTime(e.timestamp)).filter(Number.isFinite);
 const groups=correlate(events).groups;
 return {
  events:events.length,
  dated:times.length,
  time_quality:timeQuality(events),
  first:times.length?new Date(Math.min(...times)).toISOString():null,
  last:times.length?new Date(Math.max(...times)).toISOString():null,
  severity:severityCounts(findings).filter(row=>row.count),
  timeline:hourlyBuckets(events,24),
  timeline_limit:24,
  relationships:groups.slice(0,6).map(g=>({kind:g.kind,value:g.value,count:g.events.length,evidence:g.events.slice(0,8).map(e=>e.id)})),
  relationship_total:groups.length,
  reviews:feedbackMetrics(feedback,findings),
 };
}
