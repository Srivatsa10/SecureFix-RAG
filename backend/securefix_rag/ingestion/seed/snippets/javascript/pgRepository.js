/**
 * Approved pattern: node-postgres (pg) queries with numbered placeholders.
 *
 * House rules:
 * - Always call `pool.query(text, values)` or `pool.query({ text, values })`.
 * - Placeholders are $1, $2, ... in the order of the `values` array.
 * - Never build SQL with template literals or string concatenation.
 * - Dynamic sort columns go through SORT_COLUMNS; anything else is a 400.
 */
const { pool } = require('../db/pool');

const SORT_COLUMNS = Object.freeze({
  created: 'created_at',
  total: 'total_cents',
  status: 'status',
});

async function findOrderById(orderId, customerId) {
  const { rows } = await pool.query(
    'SELECT id, status, total_cents FROM orders WHERE id = $1 AND customer_id = $2',
    [orderId, customerId],
  );
  return rows[0] ?? null;
}

async function listOrders(customerId, sortKey = 'created', direction = 'desc') {
  const column = SORT_COLUMNS[sortKey];
  if (!column) {
    throw new BadRequestError(`unsupported sort key: ${sortKey}`);
  }
  const dir = direction === 'asc' ? 'ASC' : 'DESC';
  // column and dir are from fixed allowlists above, so interpolating them is safe;
  // customerId is still bound as a parameter.
  const { rows } = await pool.query({
    text: `SELECT id, status, total_cents, created_at FROM orders
           WHERE customer_id = $1 ORDER BY ${column} ${dir} LIMIT 100`,
    values: [customerId],
  });
  return rows;
}

async function searchProducts(term) {
  const { rows } = await pool.query(
    "SELECT id, name FROM products WHERE name ILIKE '%' || $1 || '%' LIMIT 50",
    [term],
  );
  return rows;
}

class BadRequestError extends Error {
  constructor(message) {
    super(message);
    this.status = 400;
  }
}

module.exports = { findOrderById, listOrders, searchProducts, BadRequestError };
