/**
 * Approved pattern: Sequelize ORM.
 *
 * House rules:
 * - Model finders with `where` objects and `Op` operators are the default.
 * - `sequelize.query` requires `replacements` (:name) or `bind` ($1); never interpolate.
 * - Do not pass request objects straight into `where` - pick the allowed fields first.
 */
const { Op, QueryTypes } = require('sequelize');
const { sequelize, Account } = require('../models');

async function findAccountsByStatus(status, createdAfter) {
  return Account.findAll({
    where: {
      status,
      createdAt: { [Op.gte]: createdAfter },
    },
    limit: 100,
  });
}

async function accountBalances(ownerId) {
  return sequelize.query(
    'SELECT id, balance_cents FROM accounts WHERE owner_id = :ownerId',
    { replacements: { ownerId }, type: QueryTypes.SELECT },
  );
}

module.exports = { findAccountsByStatus, accountBalances };
