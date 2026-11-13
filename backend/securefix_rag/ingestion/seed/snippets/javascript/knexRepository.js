/**
 * Approved pattern: Knex query builder.
 *
 * House rules:
 * - Use builder methods (`where`, `whereIn`, `orderBy`) - Knex binds values for you.
 * - `whereRaw` / `knex.raw` must use `?` (value) or `??` (identifier) bindings.
 * - Identifiers passed to `??` must still come from an allowlist.
 */
const knex = require('../db/knex');

const REPORT_COLUMNS = new Set(['region', 'channel', 'product_line']);

async function findUserByEmail(email) {
  return knex('users').select('id', 'email', 'role').where({ email }).first();
}

async function usersByIds(ids) {
  return knex('users').select('id', 'email').whereIn('id', ids);
}

async function revenueBy(column, since) {
  if (!REPORT_COLUMNS.has(column)) {
    throw new Error(`unsupported report column: ${column}`);
  }
  return knex('sales')
    .select(knex.raw('?? AS bucket, SUM(amount_cents) AS revenue', [column]))
    .whereRaw('created_at >= ?', [since])
    .groupByRaw('??', [column]);
}

module.exports = { findUserByEmail, usersByIds, revenueBy };
