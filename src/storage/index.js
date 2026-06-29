/**
 * R2-backed report storage.
 * Falls through gracefully when R2 is not bound.
 */
export class ReportStorage {
  /** @param {R2Bucket|undefined} r2 */
  constructor(r2) {
    this.r2 = r2;
  }

  get enabled() { return !!this.r2; }

  /**
   * Store a JSON report and return the R2 object key.
   */
  async saveReport(auditId, report) {
    if (!this.r2) return null;
    const key = `reports/${report.zone_id ?? report.account_id}/${auditId}.json`;
    await this.r2.put(key, JSON.stringify(report, null, 2), {
      httpMetadata: { contentType: 'application/json' },
      customMetadata: {
        zone_id: report.zone_id ?? '',
        score: String(report.summary?.score ?? 0),
        timestamp: report.timestamp,
      },
    });
    return key;
  }

  /**
   * Retrieve a stored report by its R2 key.
   */
  async getReport(key) {
    if (!this.r2) return null;
    const obj = await this.r2.get(key);
    if (!obj) return null;
    return obj.json();
  }

  /**
   * List all reports for a zone (up to 100).
   */
  async listReports(zoneId, limit = 100) {
    if (!this.r2) return [];
    const listed = await this.r2.list({ prefix: `reports/${zoneId}/`, limit });
    return listed.objects.map(o => ({
      key: o.key,
      size: o.size,
      uploaded: o.uploaded,
      score: o.customMetadata?.score,
    }));
  }
}
