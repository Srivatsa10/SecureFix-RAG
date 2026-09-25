package com.example.customers;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Approved pattern: Spring NamedParameterJdbcTemplate.
 *
 * House rules:
 * - Use named parameters (:name) with MapSqlParameterSource.
 * - Sort columns are resolved through SORT_COLUMNS; unknown keys are rejected.
 * - Never concatenate request parameters into the SQL string.
 */
@Repository
public class CustomerJdbcTemplateRepository {

    private static final Map<String, String> SORT_COLUMNS = Map.of(
            "name", "last_name",
            "joined", "created_at",
            "spend", "lifetime_spend_cents");

    private final NamedParameterJdbcTemplate jdbc;

    public CustomerJdbcTemplateRepository(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Customer> findByRegion(String region, String sortKey) {
        String column = SORT_COLUMNS.get(sortKey);
        if (column == null) {
            throw new IllegalArgumentException("unsupported sort key: " + sortKey);
        }
        String sql = "SELECT id, first_name, last_name, region FROM customers "
                + "WHERE region = :region ORDER BY " + column;
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("region", region);
        return jdbc.query(sql, params, CustomerRowMapper.INSTANCE);
    }

    public Customer findById(long id) {
        return jdbc.queryForObject(
                "SELECT id, first_name, last_name, region FROM customers WHERE id = :id",
                new MapSqlParameterSource("id", id),
                CustomerRowMapper.INSTANCE);
    }
}
