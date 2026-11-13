package com.example.accounts;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;

/**
 * Approved pattern: plain JDBC with PreparedStatement.
 *
 * House rules:
 * - java.sql.Statement with concatenated SQL is banned; always PreparedStatement.
 * - Bind every value with the typed setter (setString, setLong, ...), 1-based.
 * - try-with-resources for Connection, PreparedStatement and ResultSet.
 * - Map rows in a private method; never leak ResultSet out of the repository.
 */
public final class AccountJdbcRepository {

    private final DataSource dataSource;

    public AccountJdbcRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public Optional<Account> findByOwner(String owner) throws SQLException {
        String sql = "SELECT id, owner, balance_cents FROM accounts WHERE owner = ?";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, owner);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(mapRow(rs)) : Optional.empty();
            }
        }
    }

    public List<Account> findByStatusAndMinBalance(String status, long minBalanceCents)
            throws SQLException {
        String sql = "SELECT id, owner, balance_cents FROM accounts "
                + "WHERE status = ? AND balance_cents >= ? ORDER BY id";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setLong(2, minBalanceCents);
            try (ResultSet rs = ps.executeQuery()) {
                List<Account> accounts = new ArrayList<>();
                while (rs.next()) {
                    accounts.add(mapRow(rs));
                }
                return accounts;
            }
        }
    }

    private static Account mapRow(ResultSet rs) throws SQLException {
        return new Account(rs.getLong("id"), rs.getString("owner"), rs.getLong("balance_cents"));
    }
}
